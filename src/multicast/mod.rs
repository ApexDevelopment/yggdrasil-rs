//! Finds peers on local networks. Nodes multicast beacons advertising a
//! link-local TLS listener, and connect to the beacons they hear.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::{Map, Value};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
pub use yggdrasil_proto::advertisement::Advertisement;

use crate::admin::AdminSocket;
use crate::core::link::{Listener, format_socket_addr};
use crate::core::uri::{PeerUri, split_host_port};
use crate::core::version::{PROTOCOL_VERSION_MAJOR, PROTOCOL_VERSION_MINOR};
use crate::core::{BoxError, Core};

const GROUP_ADDR: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x114);
const GROUP_PORT: u16 = 9001;
const MAX_BEACON_INTERVAL: Duration = Duration::from_secs(15);

/// Which interfaces to beacon and listen on. Interfaces use the first entry whose regex matches.
#[derive(Clone, Debug)]
pub struct MulticastInterface {
	pub regex: Regex,
	pub beacon: bool,
	pub listen: bool,
	/// The port for the link-local listener, or 0 for any.
	pub port: u16,
	pub priority: u8,
	pub password: String,
}

#[derive(Clone)]
struct InterfaceInfo {
	index: u32,
	addrs: Vec<Ipv6Addr>,
	beacon: bool,
	listen: bool,
	port: u16,
	priority: u8,
	password: String,
	hash: Vec<u8>,
}

struct ListenerInfo {
	listener: Listener,
	time: Instant,
	interval: Duration,
}

#[derive(Default)]
struct State {
	interfaces: HashMap<String, InterfaceInfo>,
	listeners: HashMap<String, ListenerInfo>,
}

struct Inner {
	core: Core,
	config: Vec<MulticastInterface>,
	socket: Arc<UdpSocket>,
	state: Mutex<State>,
	running: AtomicBool,
	announce_now: Notify,
	cancel: CancellationToken,
}

/// The multicast module. Stops when [`Multicast::stop`] is called.
#[derive(Clone)]
pub struct Multicast {
	inner: Option<Arc<Inner>>,
}

fn password_hash(password: &str, key: &[u8]) -> Option<Vec<u8>> {
	yggdrasil_proto::handshake::password_hash(password.as_bytes(), key)
		.ok()
		.map(|hash| hash.to_vec())
}

fn bind_group_socket() -> io::Result<UdpSocket> {
	let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
	socket.set_reuse_address(true)?;
	#[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
	socket.set_reuse_port(true)?;
	socket.set_only_v6(true)?;
	socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, GROUP_PORT)).into())?;
	socket.set_nonblocking(true)?;
	UdpSocket::from_std(socket.into())
}

fn random_jitter() -> Duration {
	let mut bytes = [0u8; 4];
	let _ = getrandom::fill(&mut bytes);
	Duration::from_micros(u64::from(u32::from_le_bytes(bytes) % 1_048_576))
}

impl Multicast {
	/// Starts beaconing and listening, unless no interface is configured to do either.
	pub async fn new(core: Core, config: Vec<MulticastInterface>) -> Result<Self, BoxError> {
		if !config
			.iter()
			.any(|interface| interface.beacon || interface.listen)
		{
			return Ok(Multicast { inner: None });
		}
		log::debug!("Starting multicast module");
		let socket = Arc::new(bind_group_socket()?);
		let inner = Arc::new(Inner {
			core,
			config,
			socket,
			state: Mutex::new(State::default()),
			running: AtomicBool::new(true),
			announce_now: Notify::new(),
			cancel: CancellationToken::new(),
		});
		tokio::spawn(inner.clone().listen());
		tokio::spawn(inner.clone().announce_loop());
		log::debug!("Started multicast module");
		Ok(Multicast { inner: Some(inner) })
	}

	pub fn is_started(&self) -> bool {
		self.inner
			.as_ref()
			.is_some_and(|inner| inner.running.load(Ordering::Relaxed))
	}

	/// Sends beacons immediately rather than waiting for the next interval.
	pub fn announce_now(&self) {
		if let Some(inner) = &self.inner {
			inner.announce_now.notify_one();
		}
	}

	/// The interfaces currently in use, by name.
	pub fn interfaces(&self) -> Vec<String> {
		let Some(inner) = &self.inner else {
			return Vec::new();
		};
		let mut names: Vec<String> = inner.state().interfaces.keys().cloned().collect();
		names.sort();
		names
	}

	pub fn stop(&self) {
		if let Some(inner) = &self.inner
			&& inner.running.swap(false, Ordering::Relaxed)
		{
			log::info!("Stopping multicast module");
			inner.cancel.cancel();
			for (_, info) in inner.state().listeners.drain() {
				info.listener.cancel();
			}
		}
		log::debug!("Stopped multicast module");
	}

	pub fn setup_admin_handlers(&self, admin: &Arc<AdminSocket>) {
		let inner = self.inner.clone();
		let _ = admin.add_handler(
			"getMulticastInterfaces",
			"Show which interfaces multicast is enabled on",
			&[],
			move |_| {
				let inner = inner.clone();
				async move {
					let mut entries: Vec<(String, Value)> = Vec::new();
					if let Some(inner) = inner {
						let state = inner.state();
						for (name, info) in &state.interfaces {
							let address = state.listeners.get(name).map_or_else(
								|| "-".to_string(),
								|listener| listener.listener.local_addr().to_string(),
							);
							let mut entry = Map::new();
							entry.insert("name".into(), name.clone().into());
							entry.insert("address".into(), address.into());
							entry.insert("beacon".into(), info.beacon.into());
							entry.insert("listen".into(), info.listen.into());
							entry.insert("password".into(), (!info.password.is_empty()).into());
							entries.push((name.clone(), Value::Object(entry)));
						}
					}
					entries.sort_by(|a, b| a.0.cmp(&b.0));
					let list = entries.into_iter().map(|(_, entry)| entry).collect();
					Ok(Value::Object(Map::from_iter([(
						"multicast_interfaces".to_string(),
						Value::Array(list),
					)])))
				}
			},
		);
	}
}

impl Inner {
	fn state(&self) -> MutexGuard<'_, State> {
		self.state
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// The usable interfaces matching the configuration, with their link-local addresses.
	fn current_interfaces(&self) -> HashMap<String, InterfaceInfo> {
		let key = self.core.public_key();
		let mut interfaces = HashMap::new();
		for iface in netdev::get_interfaces() {
			if !iface.is_up()
				|| !iface.is_running()
				|| !iface.is_multicast()
				|| iface.is_point_to_point()
			{
				continue;
			}
			let Some(config) = self
				.config
				.iter()
				.filter(|config| config.beacon || config.listen)
				.find(|config| config.regex.is_match(&iface.name))
			else {
				continue;
			};
			let Some(hash) = password_hash(&config.password, &key.0) else {
				continue;
			};
			let addrs = iface
				.ipv6
				.iter()
				.map(|net| net.addr())
				.filter(Ipv6Addr::is_unicast_link_local)
				.collect();
			interfaces.insert(
				iface.name.clone(),
				InterfaceInfo {
					index: iface.index,
					addrs,
					beacon: config.beacon,
					listen: config.listen,
					port: config.port,
					priority: config.priority,
					password: config.password.clone(),
					hash,
				},
			);
		}
		interfaces
	}

	async fn announce_loop(self: Arc<Self>) {
		loop {
			self.announce().await;
			tokio::select! {
				_ = tokio::time::sleep(Duration::from_secs(1) + random_jitter()) => {}
				_ = self.announce_now.notified() => {}
				_ = self.cancel.cancelled() => return,
			}
		}
	}

	/// Stops listeners whose interface or address went away.
	fn prune_listeners(&self, state: &mut State) {
		let State {
			interfaces,
			listeners,
		} = state;
		listeners.retain(|name, info| {
			let address_present = split_host_port(info.listener.local_addr())
				.ok()
				.and_then(|(host, _)| host.split('%').next()?.parse::<Ipv6Addr>().ok())
				.is_some_and(|ip| {
					interfaces
						.get(name)
						.is_some_and(|iface| iface.addrs.contains(&ip))
				});
			if !address_present {
				info.listener.cancel();
				log::debug!("No longer multicasting on {name}");
			}
			address_present
		});
	}

	async fn announce(&self) {
		if !self.running.load(Ordering::Relaxed) {
			return;
		}
		let interfaces = self.current_interfaces();
		let to_beacon: Vec<(String, InterfaceInfo)> = {
			let mut state = self.state();
			state.interfaces = interfaces.clone();
			self.prune_listeners(&mut state);
			interfaces.into_iter().collect()
		};
		for (name, info) in to_beacon {
			let Some(addr) = info.addrs.first().copied() else {
				continue;
			};
			if info.listen {
				// Fails harmlessly if already joined
				let _ = self.socket.join_multicast_v6(&GROUP_ADDR, info.index);
			}
			if !info.beacon {
				continue;
			}
			if !self.state().listeners.contains_key(&name) {
				let uri = PeerUri {
					scheme: "tls".into(),
					user: None,
					host: format!("[{addr}]:{}", info.port),
					path: String::new(),
					query: Vec::new(),
				}
				.with_query(&[
					("priority", info.priority.to_string()),
					("password", info.password.clone()),
				]);
				match self.core.listen_local(&uri.to_string(), &name).await {
					Ok(listener) => {
						log::debug!("Started multicasting on {name}");
						self.state().listeners.insert(
							name.clone(),
							ListenerInfo {
								listener,
								time: Instant::now(),
								interval: Duration::ZERO,
							},
						);
					}
					Err(error) => {
						log::warn!("Not multicasting on {name} due to error: {error}");
						continue;
					}
				}
			}
			let port = {
				let mut state = self.state();
				let Some(listener) = state.listeners.get_mut(&name) else {
					continue;
				};
				if listener.time.elapsed() < listener.interval {
					continue;
				}
				if listener.interval < MAX_BEACON_INTERVAL {
					listener.interval += Duration::from_secs(1);
				}
				listener.time = Instant::now();
				split_host_port(listener.listener.local_addr()).map_or(0, |(_, port)| port)
			};
			let beacon = Advertisement {
				major_version: PROTOCOL_VERSION_MAJOR,
				minor_version: PROTOCOL_VERSION_MINOR,
				public_key: self.core.public_key(),
				port,
				hash: info.hash.clone(),
			};
			let destination = SocketAddrV6::new(GROUP_ADDR, GROUP_PORT, 0, info.index);
			if let Err(error) = self.socket.send_to(&beacon.encode(), destination).await {
				log::warn!("Failed to send multicast beacon: {error}");
			}
		}
	}

	async fn listen(self: Arc<Self>) {
		let mut buf = vec![0u8; 2048];
		let mut backoff = Duration::ZERO;
		loop {
			let received = tokio::select! {
				received = self.socket.recv_from(&mut buf) => received,
				_ = self.cancel.cancelled() => return,
			};
			let (n, from) = match received {
				Ok(received) => received,
				Err(error) => {
					if backoff.is_zero() {
						log::warn!("Multicast listener read error: {error}");
						backoff = Duration::from_millis(10);
					}
					tokio::time::sleep(backoff).await;
					backoff = (backoff * 2).min(Duration::from_secs(1));
					continue;
				}
			};
			backoff = Duration::ZERO;
			let SocketAddr::V6(from) = from else {
				continue;
			};
			if let Some(beacon) = Advertisement::decode(&buf[..n]) {
				self.handle_beacon(beacon, from);
			}
		}
	}

	fn handle_beacon(&self, beacon: Advertisement, from: SocketAddrV6) {
		if beacon.major_version != PROTOCOL_VERSION_MAJOR
			|| beacon.minor_version != PROTOCOL_VERSION_MINOR
			|| beacon.public_key == self.core.public_key()
		{
			return;
		}
		let interface = {
			let state = self.state();
			state
				.interfaces
				.iter()
				.find(|(_, info)| info.index == from.scope_id())
				.map(|(name, info)| (name.clone(), info.clone()))
		};
		let Some((zone, info)) = interface else {
			return;
		};
		if !info.listen
			|| password_hash(&info.password, &beacon.public_key.0).as_ref() != Some(&beacon.hash)
		{
			return;
		}
		let peer = SocketAddr::V6(SocketAddrV6::new(
			*from.ip(),
			beacon.port,
			0,
			from.scope_id(),
		));
		let uri = PeerUri {
			scheme: "tls".into(),
			user: None,
			host: format_socket_addr(&peer),
			path: String::new(),
			query: Vec::new(),
		}
		.with_query(&[
			("key", hex::encode(beacon.public_key.0)),
			("priority", info.priority.to_string()),
			("password", info.password.clone()),
		]);
		if let Err(error) = self.core.call_peer(&uri.to_string(), &zone) {
			log::debug!("Call from multicast failed: {error}");
		}
	}
}
