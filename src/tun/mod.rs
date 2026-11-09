//! The TUN adapter, which connects the operating system's IPv6 stack to the network.

use std::sync::Arc;

use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use crate::admin::AdminSocket;
use crate::config::get_defaults;
use crate::core::BoxError;
use crate::ipv6rwc::ReadWriteCloser;

const MIN_MTU: u64 = 1280;
const BUFFER_SIZE: usize = 65535;

/// Where the TUN adapter comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceSource {
	/// `auto` lets the platform pick a name; `none` or `dummy` disables the adapter.
	Name(String),
	/// An already-open TUN file descriptor, as mobile platforms provide.
	#[cfg(unix)]
	FileDescriptor(i32),
}

/// The largest MTU this platform supports.
pub fn maximum_mtu() -> u64 {
	get_defaults().maximum_if_mtu
}

fn supported_mtu(mtu: u64) -> u64 {
	mtu.clamp(MIN_MTU, maximum_mtu())
}

pub struct TunAdapter {
	enabled: bool,
	name: String,
	mtu: u64,
	cancel: CancellationToken,
}

impl TunAdapter {
	/// Creates the adapter, assigns this node's address to it, and starts moving packets.
	pub async fn new(
		rwc: ReadWriteCloser,
		source: InterfaceSource,
		mtu: u64,
	) -> Result<Arc<Self>, BoxError> {
		let cancel = CancellationToken::new();
		if matches!(&source, InterfaceSource::Name(name) if name == "none" || name == "dummy") {
			log::debug!("Not starting TUN as ifname is none or dummy");
			// Keep reading so that address mappings stay up to date
			tokio::spawn(drain(rwc, cancel.clone()));
			return Ok(Arc::new(TunAdapter {
				enabled: false,
				name: String::new(),
				mtu: 0,
				cancel,
			}));
		}
		let mtu = rwc.max_mtu().min(mtu);
		let (name, mtu) = start(rwc, source, mtu, cancel.clone()).await?;
		Ok(Arc::new(TunAdapter {
			enabled: true,
			name,
			mtu,
			cancel,
		}))
	}

	pub fn is_enabled(&self) -> bool {
		self.enabled
	}

	pub fn name(&self) -> &str {
		&self.name
	}

	pub fn mtu(&self) -> u64 {
		supported_mtu(self.mtu)
	}

	pub fn stop(&self) {
		self.cancel.cancel();
	}

	pub fn setup_admin_handlers(self: &Arc<Self>, admin: &Arc<AdminSocket>) {
		let tun = self.clone();
		let _ = admin.add_handler(
			"getTun",
			"Show information about the node's TUN interface",
			&[],
			move |_| {
				let tun = tun.clone();
				async move {
					let mut response = Map::new();
					response.insert("enabled".into(), tun.enabled.into());
					if tun.enabled {
						response.insert("name".into(), tun.name.clone().into());
						response.insert("mtu".into(), tun.mtu().into());
					}
					Ok(Value::Object(response))
				}
			},
		);
	}
}

async fn drain(rwc: ReadWriteCloser, cancel: CancellationToken) {
	let mut buf = vec![0u8; BUFFER_SIZE];
	loop {
		tokio::select! {
			read = rwc.read(&mut buf) => if read.is_err() { return },
			_ = cancel.cancelled() => return,
		}
	}
}

#[cfg(feature = "tun")]
async fn start(
	rwc: ReadWriteCloser,
	source: InterfaceSource,
	mtu: u64,
	cancel: CancellationToken,
) -> Result<(String, u64), BoxError> {
	let address = rwc.address();
	let device = match source {
		InterfaceSource::Name(name) => {
			let mut builder = tun_rs::DeviceBuilder::new()
				.mtu(mtu.min(u16::MAX as u64) as u16)
				.ipv6(address.to_ipv6(), 7u8);
			if name != "auto" {
				builder = builder.name(name);
			}
			builder
				.build_async()
				.map_err(|error| format!("failed to create TUN: {error}"))?
		}
		#[cfg(unix)]
		InterfaceSource::FileDescriptor(fd) => {
			// The caller hands over ownership of the descriptor
			unsafe { tun_rs::AsyncDevice::from_fd(fd) }
				.map_err(|error| format!("failed to use TUN file descriptor: {error}"))?
		}
	};
	let name = device.name().unwrap_or_default();
	let actual_mtu = device.mtu().map(u64::from).map(supported_mtu).unwrap_or(0);
	if actual_mtu != mtu {
		log::warn!(
			"Warning: Interface MTU {mtu} automatically adjusted to {actual_mtu} (supported range is 1280-{})",
			maximum_mtu()
		);
	}
	rwc.set_mtu(actual_mtu);
	log::info!("Interface name: {name}");
	log::info!("Interface IPv6: {address}/7");
	log::info!("Interface MTU: {actual_mtu}");
	let device = Arc::new(device);
	tokio::spawn(read_device(device.clone(), rwc.clone(), cancel.clone()));
	tokio::spawn(write_device(device, rwc, cancel));
	Ok((name, actual_mtu))
}

#[cfg(not(feature = "tun"))]
async fn start(
	_rwc: ReadWriteCloser,
	_source: InterfaceSource,
	_mtu: u64,
	_cancel: CancellationToken,
) -> Result<(String, u64), BoxError> {
	Err("built without TUN support; set IfName to \"none\"".into())
}

/// Sends packets from the operating system into the network.
#[cfg(feature = "tun")]
async fn read_device(
	device: Arc<tun_rs::AsyncDevice>,
	rwc: ReadWriteCloser,
	cancel: CancellationToken,
) {
	let mut buf = vec![0u8; BUFFER_SIZE];
	loop {
		let n = tokio::select! {
			read = device.recv(&mut buf) => match read {
				Ok(n) => n,
				Err(error) => {
					log::error!("Error reading TUN: {error}");
					return;
				}
			},
			_ = cancel.cancelled() => return,
		};
		if let Err(error) = rwc.write(&buf[..n]) {
			log::debug!("Unable to send packet: {error}");
		}
	}
}

/// Delivers packets from the network to the operating system.
#[cfg(feature = "tun")]
async fn write_device(
	device: Arc<tun_rs::AsyncDevice>,
	rwc: ReadWriteCloser,
	cancel: CancellationToken,
) {
	let mut buf = vec![0u8; BUFFER_SIZE];
	loop {
		let n = tokio::select! {
			read = rwc.read(&mut buf) => match read {
				Ok(n) => n,
				Err(error) => {
					log::error!("Exiting TUN writer due to core read error: {error}");
					return;
				}
			},
			_ = cancel.cancelled() => return,
		};
		if let Err(error) = device.send(&buf[..n]).await
			&& !cancel.is_cancelled()
		{
			log::error!("TUN iface write error: {error}");
		}
	}
}
