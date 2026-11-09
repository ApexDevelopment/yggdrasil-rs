//! Sends and receives IPv6 packets over a [`Core`], mapping Yggdrasil
//! addresses and subnets to node keys. This is what the TUN adapter uses.

mod icmpv6;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub use icmpv6::{create_icmpv6, packet_too_big};
use petrified::types::{Error, PublicKey};

use crate::address::{Address, Subnet, addr_for_key, subnet_for_key};
use crate::core::Core;

/// How long an unused key mapping or buffered packet is kept.
const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_MTU: u64 = 1280;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
	EmptyPacket,
	NotIpv6,
	Undersized(usize),
	IncorrectSource(Address),
	InvalidDestination,
}

impl fmt::Display for WriteError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			WriteError::EmptyPacket => f.write_str("empty packet"),
			WriteError::NotIpv6 => f.write_str("not an IPv6 packet"),
			WriteError::Undersized(len) => write!(f, "undersized IPv6 packet, length: {len}"),
			WriteError::IncorrectSource(addr) => write!(f, "incorrect source address: {addr}"),
			WriteError::InvalidDestination => f.write_str("invalid destination address"),
		}
	}
}

impl std::error::Error for WriteError {}

struct KeyInfo {
	address: Address,
	subnet: Subnet,
	expires: Instant,
}

struct Buffered {
	packet: Vec<u8>,
	expires: Instant,
}

#[derive(Default)]
struct KeyStore {
	keys: HashMap<PublicKey, KeyInfo>,
	by_address: HashMap<Address, PublicKey>,
	by_subnet: HashMap<Subnet, PublicKey>,
	/// The latest packet for each address or subnet whose key is being looked up.
	address_buffer: HashMap<Address, Buffered>,
	subnet_buffer: HashMap<Subnet, Buffered>,
}

impl KeyStore {
	fn expire(&mut self, now: Instant) {
		let expired: Vec<PublicKey> = self
			.keys
			.iter()
			.filter(|(_, info)| info.expires <= now)
			.map(|(key, _)| *key)
			.collect();
		for key in expired {
			if let Some(info) = self.keys.remove(&key) {
				self.by_address.remove(&info.address);
				self.by_subnet.remove(&info.subnet);
			}
		}
		self.address_buffer
			.retain(|_, buffered| buffered.expires > now);
		self.subnet_buffer
			.retain(|_, buffered| buffered.expires > now);
	}

	/// The key for a destination, refreshing its timeout.
	fn key_for(&mut self, key: Option<PublicKey>, now: Instant) -> Option<PublicKey> {
		let key = key?;
		self.keys.get_mut(&key)?.expires = now + KEY_STORE_TIMEOUT;
		Some(key)
	}

	/// Records that `key` is reachable, and returns any packets that were waiting for it.
	fn update(&mut self, key: PublicKey, now: Instant) -> Vec<Vec<u8>> {
		let mut waiting = Vec::new();
		let info = self.keys.entry(key).or_insert_with(|| KeyInfo {
			address: addr_for_key(&key),
			subnet: subnet_for_key(&key),
			expires: now,
		});
		info.expires = now + KEY_STORE_TIMEOUT;
		let (address, subnet) = (info.address, info.subnet);
		if self.by_address.insert(address, key).is_none()
			&& let Some(buffered) = self.address_buffer.remove(&address)
		{
			waiting.push(buffered.packet);
		}
		if self.by_subnet.insert(subnet, key).is_none()
			&& let Some(buffered) = self.subnet_buffer.remove(&subnet)
		{
			waiting.push(buffered.packet);
		}
		waiting
	}
}

struct Inner {
	core: Core,
	address: Address,
	subnet: Subnet,
	store: Mutex<KeyStore>,
	mtu: AtomicU64,
}

impl Inner {
	fn store(&self) -> MutexGuard<'_, KeyStore> {
		let mut store = self
			.store
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		store.expire(Instant::now());
		store
	}

	fn update(&self, key: PublicKey) -> Address {
		let waiting = self.store().update(key, Instant::now());
		for packet in waiting {
			let _ = self.core.write_to(&packet, &key);
		}
		addr_for_key(&key)
	}
}

/// Reads and writes raw IPv6 packets to and from the Yggdrasil network.
#[derive(Clone)]
pub struct ReadWriteCloser {
	inner: Arc<Inner>,
}

fn header_addresses(packet: &[u8]) -> (Address, Address, Subnet, Subnet) {
	let src: [u8; 16] = packet[8..24].try_into().expect("checked length");
	let dst: [u8; 16] = packet[24..40].try_into().expect("checked length");
	let subnet = |addr: &[u8; 16]| Subnet(addr[..8].try_into().expect("8 bytes"));
	(Address(src), Address(dst), subnet(&src), subnet(&dst))
}

impl ReadWriteCloser {
	/// Takes over `core`'s path notifications to learn which keys own which addresses.
	pub fn new(core: Core) -> Self {
		let inner = Arc::new(Inner {
			address: core.address(),
			subnet: core.subnet(),
			core: core.clone(),
			store: Mutex::new(KeyStore::default()),
			mtu: AtomicU64::new(MIN_MTU),
		});
		let weak = Arc::downgrade(&inner);
		core.set_path_notify(move |key| {
			if let Some(inner) = weak.upgrade() {
				inner.update(key);
			}
		});
		ReadWriteCloser { inner }
	}

	pub fn address(&self) -> Address {
		self.inner.address
	}

	pub fn subnet(&self) -> Subnet {
		self.inner.subnet
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
			if packet.len() < icmpv6::IPV6_HEADER_LEN || packet[0] & 0xf0 != 0x60 {
				continue;
			}
			let mtu = self.mtu();
			if packet.len() as u64 > mtu {
				if let Some(response) = packet_too_big(&packet, mtu as u32) {
					let _ = self.write(&response);
				}
				continue;
			}
			let (src_addr, dst_addr, src_subnet, dst_subnet) = header_addresses(&packet);
			if dst_addr != self.inner.address && dst_subnet != self.inner.subnet {
				continue;
			}
			let remote = self.inner.update(from);
			if src_addr != remote && src_subnet != subnet_for_key(&from) {
				continue;
			}
			let n = packet.len().min(buf.len());
			buf[..n].copy_from_slice(&packet[..n]);
			return Ok(n);
		}
	}

	/// Sends an IPv6 packet from this node. If the destination's key is not
	/// known yet, the packet waits while the key is looked up.
	pub fn write(&self, packet: &[u8]) -> Result<usize, WriteError> {
		if packet.is_empty() {
			return Err(WriteError::EmptyPacket);
		}
		if packet[0] & 0xf0 != 0x60 {
			return Err(WriteError::NotIpv6);
		}
		if packet.len() < icmpv6::IPV6_HEADER_LEN {
			return Err(WriteError::Undersized(packet.len()));
		}
		let (src_addr, dst_addr, src_subnet, dst_subnet) = header_addresses(packet);
		if src_addr != self.inner.address && src_subnet != self.inner.subnet {
			return Err(WriteError::IncorrectSource(src_addr));
		}
		if dst_addr.is_valid() {
			self.send_or_buffer(packet, |store, now| {
				let key = store.by_address.get(&dst_addr).copied();
				match store.key_for(key, now) {
					Some(key) => Ok(key),
					None => {
						store.address_buffer.insert(dst_addr, buffered(packet, now));
						Err(dst_addr.get_key())
					}
				}
			});
		} else if dst_subnet.is_valid() {
			self.send_or_buffer(packet, |store, now| {
				let key = store.by_subnet.get(&dst_subnet).copied();
				match store.key_for(key, now) {
					Some(key) => Ok(key),
					None => {
						store
							.subnet_buffer
							.insert(dst_subnet, buffered(packet, now));
						Err(dst_subnet.get_key())
					}
				}
			});
		} else {
			return Err(WriteError::InvalidDestination);
		}
		Ok(packet.len())
	}

	/// `route` returns the destination key, or the partial key to look up after buffering.
	fn send_or_buffer(
		&self,
		packet: &[u8],
		route: impl FnOnce(&mut KeyStore, Instant) -> Result<PublicKey, PublicKey>,
	) {
		let routed = route(&mut self.inner.store(), Instant::now());
		match routed {
			Ok(key) => {
				let _ = self.inner.core.write_to(packet, &key);
			}
			Err(partial) => self.inner.core.send_lookup(&partial),
		}
	}

	pub fn close(&self) {
		self.inner.core.stop();
	}
}

fn buffered(packet: &[u8], now: Instant) -> Buffered {
	Buffered {
		packet: packet.to_vec(),
		expires: now + KEY_STORE_TIMEOUT,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn update_releases_buffered_packets_once() {
		let mut store = KeyStore::default();
		let key = PublicKey([0x42; 32]);
		let now = Instant::now();
		store
			.address_buffer
			.insert(addr_for_key(&key), buffered(b"to address", now));
		store
			.subnet_buffer
			.insert(subnet_for_key(&key), buffered(b"to subnet", now));
		assert_eq!(
			store.update(key, now),
			vec![b"to address".to_vec(), b"to subnet".to_vec()]
		);
		assert!(store.update(key, now).is_empty());
	}

	#[test]
	fn mappings_expire() {
		let mut store = KeyStore::default();
		let key = PublicKey([0x42; 32]);
		let now = Instant::now();
		store.update(key, now);
		store.expire(now + KEY_STORE_TIMEOUT / 2);
		assert!(store.by_address.contains_key(&addr_for_key(&key)));
		store.expire(now + KEY_STORE_TIMEOUT);
		assert!(store.keys.is_empty() && store.by_address.is_empty() && store.by_subnet.is_empty());
	}
}
