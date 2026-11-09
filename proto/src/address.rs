//! Yggdrasil's IPv6 addresses and /64 subnets, derived from node public keys.

use std::fmt;
use std::net::Ipv6Addr;

use petrified::types::PublicKey;

/// The first byte of every Yggdrasil address. Subnets set its lowest bit.
pub const PREFIX: u8 = 0x02;

/// An IPv6 address in the Yggdrasil range (`200::/8`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Address(pub [u8; 16]);

/// An IPv6 /64 subnet in the Yggdrasil range (`300::/8`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Subnet(pub [u8; 8]);

impl Address {
	/// Whether this address belongs to a node rather than a subnet.
	pub fn is_valid(&self) -> bool {
		self.0[0] == PREFIX
	}

	/// The key bits recoverable from this address, with the rest set to 1.
	/// Used to look up the node owning the address.
	pub fn get_key(&self) -> PublicKey {
		let mut key = [0u8; 32];
		let ones = self.0[1] as usize;
		for idx in 0..ones.min(256) {
			key[idx / 8] |= 0x80 >> (idx % 8);
		}
		let key_offset = ones + 1;
		let addr_offset = 16;
		for idx in addr_offset..128 {
			let mut bits = self.0[idx / 8] & (0x80 >> (idx % 8));
			bits <<= idx % 8;
			let key_idx = key_offset + (idx - addr_offset);
			bits >>= key_idx % 8;
			let byte = key_idx / 8;
			if byte >= key.len() {
				break;
			}
			key[byte] |= bits;
		}
		for byte in &mut key {
			*byte = !*byte;
		}
		PublicKey(key)
	}

	pub fn to_ipv6(&self) -> Ipv6Addr {
		Ipv6Addr::from(self.0)
	}
}

impl Subnet {
	pub fn is_valid(&self) -> bool {
		self.0[0] == PREFIX | 0x01
	}

	pub fn get_key(&self) -> PublicKey {
		let mut addr = [0u8; 16];
		addr[..8].copy_from_slice(&self.0);
		Address(addr).get_key()
	}

	/// The first address of the subnet.
	pub fn to_ipv6(&self) -> Ipv6Addr {
		let mut addr = [0u8; 16];
		addr[..8].copy_from_slice(&self.0);
		Ipv6Addr::from(addr)
	}
}

impl From<Ipv6Addr> for Address {
	fn from(ip: Ipv6Addr) -> Self {
		Address(ip.octets())
	}
}

impl fmt::Display for Address {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		self.to_ipv6().fmt(f)
	}
}

impl fmt::Display for Subnet {
	/// CIDR notation, like `300:1234:5678:9abc::/64`.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}/64", self.to_ipv6())
	}
}

/// The node address for a key: the prefix, then the number of leading ones in
/// the inverted key, then the inverted key after those ones and the first zero.
pub fn addr_for_key(key: &PublicKey) -> Address {
	let inverted = key.0.map(|byte| !byte);
	let mut addr = [0u8; 16];
	addr[0] = PREFIX;
	let mut ones = 0u8;
	let mut counting_ones = true;
	let mut acc = 0u8;
	let mut acc_bits = 0;
	let mut out = 2;
	for idx in 0..256 {
		let bit = (inverted[idx / 8] >> (7 - idx % 8)) & 1;
		if counting_ones {
			if bit == 1 {
				ones = ones.wrapping_add(1);
			} else {
				counting_ones = false;
			}
			continue;
		}
		acc = (acc << 1) | bit;
		acc_bits += 1;
		if acc_bits == 8 {
			acc_bits = 0;
			if out < addr.len() {
				addr[out] = acc;
				out += 1;
			}
		}
	}
	addr[1] = ones;
	Address(addr)
}

/// The /64 subnet for a key: the node address with the subnet bit set, truncated.
pub fn subnet_for_key(key: &PublicKey) -> Subnet {
	let addr = addr_for_key(key);
	let mut subnet = [0u8; 8];
	subnet.copy_from_slice(&addr.0[..8]);
	subnet[0] |= 0x01;
	Subnet(subnet)
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	const KEY: [u8; 32] = [
		189, 186, 207, 216, 34, 64, 222, 61, 205, 18, 57, 36, 203, 181, 82, 86, 251, 141, 171, 8,
		170, 152, 227, 5, 82, 138, 184, 79, 65, 158, 110, 251,
	];
	const ADDRESS: [u8; 16] = [
		2, 0, 132, 138, 96, 79, 187, 126, 67, 132, 101, 219, 141, 182, 104, 149,
	];
	const SUBNET: [u8; 8] = [3, 0, 132, 138, 96, 79, 187, 126];

	// Vectors from yggdrasil-go's address_test.go
	#[test]
	fn derives_go_vectors() {
		assert_eq!(addr_for_key(&PublicKey(KEY)).0, ADDRESS);
		assert_eq!(subnet_for_key(&PublicKey(KEY)).0, SUBNET);
		let mut address_key = [255u8; 32];
		address_key[..14].copy_from_slice(&KEY[..14]);
		address_key[14] = 127;
		assert_eq!(Address(ADDRESS).get_key().0, address_key);
		let mut subnet_key = [255u8; 32];
		subnet_key[..6].copy_from_slice(&KEY[..6]);
		assert_eq!(Subnet(SUBNET).get_key().0, subnet_key);
	}

	#[test]
	fn validity_depends_on_prefix() {
		assert!(!Address([0; 16]).is_valid());
		assert!(!Address([3; 16]).is_valid());
		assert!(Address([2; 16]).is_valid());
		assert!(!Subnet([2; 8]).is_valid());
		assert!(Subnet([3; 8]).is_valid());
	}

	proptest! {
		#[test]
		fn address_key_prefix_matches(key in any::<[u8; 32]>()) {
			let key = PublicKey(key);
			let addr = addr_for_key(&key);
			prop_assert!(addr.is_valid());
			// The partial key must agree with the real key on every bit the address encodes.
			let ones = addr.0[1] as usize;
			let known_bits = (ones + 1 + 112).min(256);
			let partial = addr.get_key();
			for bit in 0..known_bits {
				let mask = 0x80 >> (bit % 8);
				prop_assert_eq!(partial.0[bit / 8] & mask, key.0[bit / 8] & mask, "bit {}", bit);
			}
		}

		#[test]
		fn subnet_key_prefix_matches(key in any::<[u8; 32]>()) {
			let key = PublicKey(key);
			let subnet = subnet_for_key(&key);
			prop_assert!(subnet.is_valid());
			let ones = subnet.0[1] as usize;
			let known_bits = (ones + 1 + 48).min(256);
			let partial = subnet.get_key();
			for bit in 0..known_bits {
				let mask = 0x80 >> (bit % 8);
				prop_assert_eq!(partial.0[bit / 8] & mask, key.0[bit / 8] & mask, "bit {}", bit);
			}
		}

		#[test]
		fn address_round_trips_through_its_partial_key(key in any::<[u8; 32]>()) {
			let addr = addr_for_key(&PublicKey(key));
			prop_assert_eq!(addr_for_key(&addr.get_key()), addr);
		}
	}
}
