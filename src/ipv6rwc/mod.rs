//! Sends and receives IPv6 packets over a [`Core`], mapping Yggdrasil
//! addresses and subnets to node keys with [`yggdrasil_proto::ipv6`]. This is
//! what the TUN adapter uses.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use petrified::types::{Error, PublicKey};
pub use yggdrasil_proto::icmpv6::{create_icmpv6, packet_too_big};
pub use yggdrasil_proto::ipv6::WriteError;
use yggdrasil_proto::ipv6::{Incoming, KeyStore, Outgoing};

use crate::address::{Address, Subnet};
use crate::core::Core;

const MIN_MTU: u64 = 1280;

struct Inner {
	core: Core,
	store: Mutex<KeyStore>,
	mtu: AtomicU64,
}

impl Inner {
	fn store(&self) -> MutexGuard<'_, KeyStore> {
		let mut store = self
			.store
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		store.expire(self.core.now());
		store
	}

	fn send_all(&self, packets: Vec<Vec<u8>>, key: &PublicKey) {
		for packet in packets {
			let _ = self.core.write_to(&packet, key);
		}
	}
}

/// Reads and writes raw IPv6 packets to and from the Yggdrasil network.
#[derive(Clone)]
pub struct ReadWriteCloser {
	inner: Arc<Inner>,
}

impl ReadWriteCloser {
	/// Takes over `core`'s path notifications to learn which keys own which addresses.
	pub fn new(core: Core) -> Self {
		let inner = Arc::new(Inner {
			store: Mutex::new(KeyStore::new(&core.public_key())),
			core: core.clone(),
			mtu: AtomicU64::new(MIN_MTU),
		});
		let weak = Arc::downgrade(&inner);
		core.set_path_notify(move |key| {
			if let Some(inner) = weak.upgrade() {
				let released = inner.store().update(key, inner.core.now());
				inner.send_all(released, &key);
			}
		});
		ReadWriteCloser { inner }
	}

	pub fn address(&self) -> Address {
		self.inner.core.address()
	}

	pub fn subnet(&self) -> Subnet {
		self.inner.core.subnet()
	}

	pub fn max_mtu(&self) -> u64 {
		self.inner.core.mtu()
	}

	/// Sets the MTU, clamped between 1280 and [`ReadWriteCloser::max_mtu`].
	pub fn set_mtu(&self, mtu: u64) {
		let mtu = mtu.min(self.max_mtu()).max(MIN_MTU);
		self.inner.mtu.store(mtu, Ordering::Relaxed);
	}

	pub fn mtu(&self) -> u64 {
		self.inner.mtu.load(Ordering::Relaxed)
	}

	/// Waits for the next valid IPv6 packet for this node, copying it into `buf`.
	/// Packets larger than the MTU are dropped, and their sender told to use a smaller one.
	pub async fn read(&self, buf: &mut [u8]) -> Result<usize, Error> {
		loop {
			let (from, packet) = self.inner.core.recv().await?;
			let (verdict, released) =
				self.inner
					.store()
					.incoming(from, &packet, self.mtu(), self.inner.core.now());
			self.inner.send_all(released, &from);
			match verdict {
				Incoming::Deliver => {
					let n = packet.len().min(buf.len());
					buf[..n].copy_from_slice(&packet[..n]);
					return Ok(n);
				}
				Incoming::TooBig(reply) => {
					let _ = self.write(&reply);
				}
				Incoming::Drop => {}
			}
		}
	}

	/// Sends an IPv6 packet from this node. If the destination's key is not
	/// known yet, the packet waits while the key is looked up.
	pub fn write(&self, packet: &[u8]) -> Result<usize, WriteError> {
		let outgoing = self.inner.store().outgoing(packet, self.inner.core.now())?;
		match outgoing {
			Outgoing::Send(key) => {
				let _ = self.inner.core.write_to(packet, &key);
			}
			Outgoing::Lookup(partial) => self.inner.core.send_lookup(&partial),
		}
		Ok(packet.len())
	}

	pub fn close(&self) {
		self.inner.core.stop();
	}
}
