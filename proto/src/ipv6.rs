//! Maps Yggdrasil IPv6 addresses and subnets to node keys, as yggdrasil-go's
//! `ipv6rwc` does. Callers move the packets and keep the clock; this module
//! decides where each packet goes.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use petrified::types::{Instant, PublicKey};

use crate::address::{Address, Subnet, addr_for_key, subnet_for_key};
use crate::icmpv6::{IPV6_HEADER_LEN, packet_too_big};

/// How long an unused key mapping or buffered packet is kept.
pub const KEY_STORE_TIMEOUT: Duration = Duration::from_secs(2 * 60);

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

impl core::error::Error for WriteError {}

/// Where an outgoing packet should go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outgoing {
	/// Send the packet to this node.
	Send(PublicKey),
	/// The destination's key is unknown, and the packet is held. Look up this
	/// partial key; when a path is found, [`KeyStore::update`] releases the packet.
	Lookup(PublicKey),
}

/// What to do with a packet from the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
	/// Deliver the packet to the local host.
	Deliver,
	Drop,
	/// The packet exceeds the MTU. Drop it, and route this ICMPv6 "packet too
	/// big" message back to its sender as an outgoing packet.
	TooBig(Vec<u8>),
}

#[derive(Debug)]
struct KeyInfo {
	address: Address,
	subnet: Subnet,
	expires: Instant,
}

#[derive(Debug)]
struct Buffered {
	packet: Vec<u8>,
	expires: Instant,
}

/// The keys this node knows for remote addresses and subnets.
#[derive(Debug)]
pub struct KeyStore {
	address: Address,
	subnet: Subnet,
	keys: BTreeMap<PublicKey, KeyInfo>,
	by_address: BTreeMap<Address, PublicKey>,
	by_subnet: BTreeMap<Subnet, PublicKey>,
	/// The latest packet for each address or subnet whose key is being looked up.
	address_buffer: BTreeMap<Address, Buffered>,
	subnet_buffer: BTreeMap<Subnet, Buffered>,
}

fn header_addresses(packet: &[u8]) -> (Address, Address, Subnet, Subnet) {
	let src: [u8; 16] = packet[8..24].try_into().expect("checked length");
	let dst: [u8; 16] = packet[24..40].try_into().expect("checked length");
	let subnet = |addr: &[u8; 16]| Subnet(addr[..8].try_into().expect("8 bytes"));
	(Address(src), Address(dst), subnet(&src), subnet(&dst))
}

fn buffered(packet: &[u8], now: Instant) -> Buffered {
	Buffered {
		packet: packet.to_vec(),
		expires: now + KEY_STORE_TIMEOUT,
	}
}

impl KeyStore {
	/// A store for the node with this key.
	pub fn new(own_key: &PublicKey) -> Self {
		KeyStore {
			address: addr_for_key(own_key),
			subnet: subnet_for_key(own_key),
			keys: BTreeMap::new(),
			by_address: BTreeMap::new(),
			by_subnet: BTreeMap::new(),
			address_buffer: BTreeMap::new(),
			subnet_buffer: BTreeMap::new(),
		}
	}

	pub fn address(&self) -> Address {
		self.address
	}

	pub fn subnet(&self) -> Subnet {
		self.subnet
	}

	/// Forgets mappings and packets unused for [`KEY_STORE_TIMEOUT`].
	pub fn expire(&mut self, now: Instant) {
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

	/// Records that `key` is reachable, as when a path to it is found, and
	/// returns the packets that were waiting for it. Send them to `key`.
	pub fn update(&mut self, key: PublicKey, now: Instant) -> Vec<Vec<u8>> {
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

	/// Decides where a packet from the local host goes. If the destination's
	/// key is unknown, the packet is held until [`KeyStore::update`] releases it.
	pub fn outgoing(&mut self, packet: &[u8], now: Instant) -> Result<Outgoing, WriteError> {
		if packet.is_empty() {
			return Err(WriteError::EmptyPacket);
		}
		if packet[0] & 0xf0 != 0x60 {
			return Err(WriteError::NotIpv6);
		}
		if packet.len() < IPV6_HEADER_LEN {
			return Err(WriteError::Undersized(packet.len()));
		}
		let (src_addr, dst_addr, src_subnet, dst_subnet) = header_addresses(packet);
		if src_addr != self.address && src_subnet != self.subnet {
			return Err(WriteError::IncorrectSource(src_addr));
		}
		if dst_addr.is_valid() {
			let key = self.by_address.get(&dst_addr).copied();
			Ok(match self.key_for(key, now) {
				Some(key) => Outgoing::Send(key),
				None => {
					self.address_buffer.insert(dst_addr, buffered(packet, now));
					Outgoing::Lookup(dst_addr.get_key())
				}
			})
		} else if dst_subnet.is_valid() {
			let key = self.by_subnet.get(&dst_subnet).copied();
			Ok(match self.key_for(key, now) {
				Some(key) => Outgoing::Send(key),
				None => {
					self.subnet_buffer.insert(dst_subnet, buffered(packet, now));
					Outgoing::Lookup(dst_subnet.get_key())
				}
			})
		} else {
			Err(WriteError::InvalidDestination)
		}
	}

	/// Decides what to do with a packet `from` another node. Accepting a packet
	/// may release held ones, returned alongside; send those to `from`.
	pub fn incoming(
		&mut self,
		from: PublicKey,
		packet: &[u8],
		mtu: u64,
		now: Instant,
	) -> (Incoming, Vec<Vec<u8>>) {
		if packet.len() < IPV6_HEADER_LEN || packet[0] & 0xf0 != 0x60 {
			return (Incoming::Drop, Vec::new());
		}
		if packet.len() as u64 > mtu {
			let reply = packet_too_big(packet, mtu as u32).map_or(Incoming::Drop, Incoming::TooBig);
			return (reply, Vec::new());
		}
		let (src_addr, dst_addr, src_subnet, dst_subnet) = header_addresses(packet);
		if dst_addr != self.address && dst_subnet != self.subnet {
			return (Incoming::Drop, Vec::new());
		}
		let released = self.update(from, now);
		let verdict = if src_addr != addr_for_key(&from) && src_subnet != subnet_for_key(&from) {
			Incoming::Drop
		} else {
			Incoming::Deliver
		};
		(verdict, released)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use alloc::vec;
	use core::net::Ipv6Addr;
	use proptest::prelude::*;

	const MINE: PublicKey = PublicKey([0x11; 32]);
	const THEIRS: PublicKey = PublicKey([0x42; 32]);

	fn at(seconds: u64) -> Instant {
		Instant::from_duration(Duration::from_secs(seconds))
	}

	fn packet(src: Ipv6Addr, dst: Ipv6Addr, len: usize) -> Vec<u8> {
		let mut packet = vec![0u8; len.max(IPV6_HEADER_LEN)];
		packet[0] = 0x60;
		packet[8..24].copy_from_slice(&src.octets());
		packet[24..40].copy_from_slice(&dst.octets());
		packet
	}

	fn mine() -> Ipv6Addr {
		addr_for_key(&MINE).to_ipv6()
	}

	fn theirs() -> Ipv6Addr {
		addr_for_key(&THEIRS).to_ipv6()
	}

	#[test]
	fn holds_packets_until_the_key_is_known() {
		let mut store = KeyStore::new(&MINE);
		let to_address = packet(mine(), theirs(), 48);
		let mut subnet_host = subnet_for_key(&THEIRS).to_ipv6().octets();
		subnet_host[15] = 1;
		let to_subnet = packet(mine(), Ipv6Addr::from(subnet_host), 48);
		assert_eq!(
			store.outgoing(&to_address, at(0)),
			Ok(Outgoing::Lookup(addr_for_key(&THEIRS).get_key()))
		);
		assert_eq!(
			store.outgoing(&to_subnet, at(0)),
			Ok(Outgoing::Lookup(subnet_for_key(&THEIRS).get_key()))
		);
		assert_eq!(
			store.update(THEIRS, at(1)),
			vec![to_address.clone(), to_subnet]
		);
		assert!(store.update(THEIRS, at(1)).is_empty());
		assert_eq!(
			store.outgoing(&to_address, at(2)),
			Ok(Outgoing::Send(THEIRS))
		);
	}

	#[test]
	fn mappings_expire() {
		let mut store = KeyStore::new(&MINE);
		store.update(THEIRS, at(0));
		store.expire(at(0) + KEY_STORE_TIMEOUT / 2);
		assert!(store.by_address.contains_key(&addr_for_key(&THEIRS)));
		store.expire(at(0) + KEY_STORE_TIMEOUT);
		assert!(store.keys.is_empty() && store.by_address.is_empty() && store.by_subnet.is_empty());
	}

	#[test]
	fn rejects_bad_outgoing_packets() {
		let mut store = KeyStore::new(&MINE);
		assert_eq!(store.outgoing(&[], at(0)), Err(WriteError::EmptyPacket));
		assert_eq!(store.outgoing(&[0x45; 40], at(0)), Err(WriteError::NotIpv6));
		assert_eq!(
			store.outgoing(&[0x60; 20], at(0)),
			Err(WriteError::Undersized(20))
		);
		assert_eq!(
			store.outgoing(&packet(theirs(), theirs(), 40), at(0)),
			Err(WriteError::IncorrectSource(addr_for_key(&THEIRS)))
		);
		assert_eq!(
			store.outgoing(&packet(mine(), Ipv6Addr::LOCALHOST, 40), at(0)),
			Err(WriteError::InvalidDestination)
		);
	}

	#[test]
	fn checks_incoming_packets() {
		let mut store = KeyStore::new(&MINE);
		assert_eq!(
			store
				.incoming(THEIRS, &packet(theirs(), mine(), 100), 1280, at(0))
				.0,
			Incoming::Deliver
		);
		// Spoofed source
		assert_eq!(
			store
				.incoming(THEIRS, &packet(mine(), mine(), 100), 1280, at(0))
				.0,
			Incoming::Drop
		);
		// Not for this node
		assert_eq!(
			store
				.incoming(THEIRS, &packet(theirs(), theirs(), 100), 1280, at(0))
				.0,
			Incoming::Drop
		);
		let (verdict, _) = store.incoming(THEIRS, &packet(theirs(), mine(), 1400), 1280, at(0));
		let Incoming::TooBig(reply) = verdict else {
			panic!("expected packet too big, got {verdict:?}");
		};
		// The reply goes from this node back to the sender
		assert_eq!(store.outgoing(&reply, at(0)), Ok(Outgoing::Send(THEIRS)));
	}

	proptest! {
		#[test]
		fn never_panics_on_arbitrary_packets(data in proptest::collection::vec(any::<u8>(), 0..200), mtu in 0u64..300) {
			let mut store = KeyStore::new(&MINE);
			let _ = store.outgoing(&data, at(0));
			let _ = store.incoming(THEIRS, &data, mtu, at(0));
		}
	}
}
