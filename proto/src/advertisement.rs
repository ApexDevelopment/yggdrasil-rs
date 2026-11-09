use petrified::types::PublicKey;

/// The beacon a node multicasts to announce its link-local listener.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advertisement {
	pub major_version: u16,
	pub minor_version: u16,
	pub public_key: PublicKey,
	pub port: u16,
	/// BLAKE2b-512 of the public key, keyed with the interface's password.
	pub hash: Vec<u8>,
}

const HEADER_LEN: usize = 32 + 8;

impl Advertisement {
	pub fn encode(&self) -> Vec<u8> {
		let mut out = Vec::with_capacity(HEADER_LEN + self.hash.len());
		out.extend_from_slice(&self.major_version.to_be_bytes());
		out.extend_from_slice(&self.minor_version.to_be_bytes());
		out.extend_from_slice(&self.public_key.0);
		out.extend_from_slice(&self.port.to_be_bytes());
		out.extend_from_slice(&(self.hash.len() as u16).to_be_bytes());
		out.extend_from_slice(&self.hash);
		out
	}

	/// Decodes a beacon. Bytes after the hash are ignored, as in Go.
	pub fn decode(data: &[u8]) -> Option<Self> {
		if data.len() < HEADER_LEN {
			return None;
		}
		let u16_at = |at: usize| u16::from_be_bytes([data[at], data[at + 1]]);
		let hash_len = u16_at(4 + 32 + 2) as usize;
		let hash = data.get(HEADER_LEN..HEADER_LEN + hash_len)?;
		Some(Advertisement {
			major_version: u16_at(0),
			minor_version: u16_at(2),
			public_key: PublicKey(data[4..36].try_into().expect("32 bytes")),
			port: u16_at(36),
			hash: hash.to_vec(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn round_trips(
			major_version in any::<u16>(),
			minor_version in any::<u16>(),
			key in any::<[u8; 32]>(),
			port in any::<u16>(),
			hash in proptest::collection::vec(any::<u8>(), 0..128),
		) {
			let advertisement = Advertisement { major_version, minor_version, public_key: PublicKey(key), port, hash };
			prop_assert_eq!(Advertisement::decode(&advertisement.encode()), Some(advertisement));
		}

		#[test]
		fn truncation_is_rejected(key in any::<[u8; 32]>(), hash in proptest::collection::vec(any::<u8>(), 1..64), cut in 1usize..64) {
			let advertisement = Advertisement { major_version: 0, minor_version: 5, public_key: PublicKey(key), port: 1, hash };
			let encoded = advertisement.encode();
			let cut = cut.min(encoded.len());
			prop_assert_eq!(Advertisement::decode(&encoded[..encoded.len() - cut]), None);
		}
	}
}
