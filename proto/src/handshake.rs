//! The metadata exchanged at the start of every peer link, before Ironwood
//! takes over the stream.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use petrified::types::{PrivateKey, PublicKey, SIGNATURE_SIZE};

pub const PROTOCOL_VERSION_MAJOR: u16 = 0;
pub const PROTOCOL_VERSION_MINOR: u16 = 5;

const META_VERSION_MAJOR: u16 = 0;
const META_VERSION_MINOR: u16 = 1;
const META_PUBLIC_KEY: u16 = 2;
const META_PRIORITY: u16 = 3;

/// The longest password BLAKE2b accepts as a key.
pub const MAX_PASSWORD_LEN: usize = 64;
/// The `meta` preamble and the length of the rest.
pub const HEADER_LEN: usize = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandshakeError {
	InvalidPreamble,
	InvalidLength,
	InvalidPassword,
	IncorrectPassword,
	HashFailure,
	/// The password is too long to key BLAKE2b with.
	KeySize,
	Io(String),
}

impl fmt::Display for HandshakeError {
	/// Uses the same messages as yggdrasil-go.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			HandshakeError::InvalidPreamble => {
				f.write_str("invalid handshake, remote side is not Yggdrasil")
			}
			HandshakeError::InvalidLength => {
				f.write_str("invalid handshake length, possible version mismatch")
			}
			HandshakeError::InvalidPassword => {
				f.write_str("invalid password supplied, check your config")
			}
			HandshakeError::IncorrectPassword => f.write_str("password does not match remote side"),
			HandshakeError::HashFailure => f.write_str("invalid hash length"),
			HandshakeError::KeySize => f.write_str("blake2b: invalid key size"),
			HandshakeError::Io(error) => f.write_str(error),
		}
	}
}

impl core::error::Error for HandshakeError {}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Metadata {
	pub major_ver: u16,
	pub minor_ver: u16,
	/// Empty until decoded, as a remote might omit it.
	pub public_key: Option<PublicKey>,
	pub priority: u8,
}

/// Hashes a key with the link password, which the handshake signature covers.
pub fn password_hash(password: &[u8], key: &[u8]) -> Result<[u8; 64], HandshakeError> {
	if password.len() > MAX_PASSWORD_LEN {
		return Err(HandshakeError::KeySize);
	}
	let hash = blake2b_simd::Params::new()
		.hash_length(64)
		.key(password)
		.hash(key);
	Ok(hash.as_bytes().try_into().expect("64-byte hash"))
}

impl Metadata {
	/// Metadata for this node's protocol version.
	pub fn base() -> Self {
		Metadata {
			major_ver: PROTOCOL_VERSION_MAJOR,
			minor_ver: PROTOCOL_VERSION_MINOR,
			public_key: None,
			priority: 0,
		}
	}

	pub fn encode(&self, secret: &PrivateKey, password: &[u8]) -> Result<Vec<u8>, HandshakeError> {
		let key = self.public_key.unwrap_or_default();
		let mut bs = Vec::with_capacity(128);
		bs.extend_from_slice(b"meta");
		bs.extend_from_slice(&[0, 0]);
		for (field, value) in [
			(META_VERSION_MAJOR, &self.major_ver.to_be_bytes()[..]),
			(META_VERSION_MINOR, &self.minor_ver.to_be_bytes()[..]),
			(META_PUBLIC_KEY, &key.0[..]),
			(META_PRIORITY, &[self.priority][..]),
		] {
			bs.extend_from_slice(&field.to_be_bytes());
			bs.extend_from_slice(&(value.len() as u16).to_be_bytes());
			bs.extend_from_slice(value);
		}
		let hash = password_hash(password, &key.0)?;
		bs.extend_from_slice(&secret.sign(&hash));
		let remaining = (bs.len() - 6) as u16;
		bs[4..6].copy_from_slice(&remaining.to_be_bytes());
		Ok(bs)
	}

	/// Checks the fixed header, and returns the length of the body that follows it.
	pub fn body_length(header: &[u8; HEADER_LEN]) -> Result<usize, HandshakeError> {
		if &header[..4] != b"meta" {
			return Err(HandshakeError::InvalidPreamble);
		}
		let length = u16::from_be_bytes([header[4], header[5]]) as usize;
		if length < SIGNATURE_SIZE {
			return Err(HandshakeError::InvalidLength);
		}
		Ok(length)
	}

	/// Decodes and verifies a complete encoding: the header, then the body.
	pub fn decode(data: &[u8], password: &[u8]) -> Result<Self, HandshakeError> {
		let eof = |read: usize| {
			HandshakeError::Io(if read == 0 { "EOF" } else { "unexpected EOF" }.into())
		};
		let header = data.get(..HEADER_LEN).ok_or(eof(data.len()))?;
		let length = Self::body_length(header.try_into().expect("6 bytes"))?;
		let body = data.get(6..6 + length).ok_or(eof(data.len() - 6))?;
		Self::decode_body(body, password)
	}

	/// Decodes everything after the 6-byte header.
	pub fn decode_body(body: &[u8], password: &[u8]) -> Result<Self, HandshakeError> {
		if body.len() < SIGNATURE_SIZE {
			return Err(HandshakeError::InvalidLength);
		}
		let (mut fields, sig) = body.split_at(body.len() - SIGNATURE_SIZE);
		let mut meta = Metadata::default();
		while fields.len() >= 4 {
			let op = u16::from_be_bytes([fields[0], fields[1]]);
			let op_len = u16::from_be_bytes([fields[2], fields[3]]) as usize;
			fields = &fields[4..];
			if fields.len() < op_len {
				return Err(HandshakeError::InvalidLength);
			}
			let (field, rest) = fields.split_at(op_len);
			match op {
				META_VERSION_MAJOR => meta.major_ver = decode_u16(field)?,
				META_VERSION_MINOR => meta.minor_ver = decode_u16(field)?,
				META_PUBLIC_KEY => {
					let key: [u8; 32] = field
						.try_into()
						.map_err(|_| HandshakeError::InvalidLength)?;
					meta.public_key = Some(PublicKey(key));
				}
				META_PRIORITY => {
					let [priority] = field else {
						return Err(HandshakeError::InvalidLength);
					};
					meta.priority = *priority;
				}
				_ => {}
			}
			fields = rest;
		}
		if !fields.is_empty() {
			return Err(HandshakeError::InvalidLength);
		}
		if password.len() > MAX_PASSWORD_LEN {
			return Err(HandshakeError::InvalidPassword);
		}
		let Some(key) = meta.public_key else {
			return Err(HandshakeError::HashFailure);
		};
		let hash = password_hash(password, &key.0)?;
		let sig: &[u8; SIGNATURE_SIZE] = sig.try_into().expect("split at signature size");
		if !key.verify(&hash, sig) {
			return Err(HandshakeError::IncorrectPassword);
		}
		Ok(meta)
	}

	/// Whether the remote runs a compatible protocol version.
	pub fn check(&self) -> bool {
		self.major_ver == PROTOCOL_VERSION_MAJOR
			&& self.minor_ver == PROTOCOL_VERSION_MINOR
			&& self.public_key.is_some()
	}
}

fn decode_u16(field: &[u8]) -> Result<u16, HandshakeError> {
	let bytes: [u8; 2] = field
		.try_into()
		.map_err(|_| HandshakeError::InvalidLength)?;
	Ok(u16::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	fn metadata(seed: [u8; 32], major: u16, minor: u16, priority: u8) -> (PrivateKey, Metadata) {
		let secret = PrivateKey::from_seed(&seed);
		let meta = Metadata {
			major_ver: major,
			minor_ver: minor,
			public_key: Some(secret.public_key()),
			priority,
		};
		(secret, meta)
	}

	#[test]
	fn password_must_match() {
		let cases: [(&[u8], &[u8], bool); 5] = [
			(b"", b"", true),
			(b"", b"foo", false),
			(b"foo", b"", false),
			(b"foo", b"foo", true),
			(b"foo", b"bar", false),
		];
		for (local, remote, allowed) in cases {
			let (secret, meta) = metadata([7; 32], 0, 5, 0);
			let encoded = meta.encode(&secret, local).unwrap();
			let decoded = Metadata::decode_body(&encoded[6..], remote);
			assert_eq!(decoded.is_ok(), allowed, "{local:?} -> {remote:?}");
		}
	}

	#[test]
	fn rejects_overlong_password() {
		let (secret, meta) = metadata([1; 32], 0, 5, 0);
		assert_eq!(
			meta.encode(&secret, &[b'x'; 65]),
			Err(HandshakeError::KeySize)
		);
	}

	proptest! {
		#[test]
		fn round_trips(
			seed in any::<[u8; 32]>(),
			major in any::<u16>(),
			minor in any::<u16>(),
			priority in any::<u8>(),
			password in proptest::collection::vec(any::<u8>(), 0..=64),
		) {
			let (secret, meta) = metadata(seed, major, minor, priority);
			let encoded = meta.encode(&secret, &password).unwrap();
			prop_assert_eq!(&encoded[..4], b"meta");
			let length = u16::from_be_bytes([encoded[4], encoded[5]]) as usize;
			prop_assert_eq!(length, encoded.len() - 6);
			prop_assert_eq!(Metadata::decode_body(&encoded[6..], &password), Ok(meta));
		}

		#[test]
		fn decoding_garbage_never_panics(body in proptest::collection::vec(any::<u8>(), 0..256)) {
			let _ = Metadata::decode_body(&body, b"");
		}

		#[test]
		fn corrupt_key_or_signature_is_rejected(seed in any::<[u8; 32]>(), index in any::<prop::sample::Index>(), flip in 1u8..) {
			let (secret, meta) = metadata(seed, 0, 5, 0);
			let mut encoded = meta.encode(&secret, b"").unwrap();
			// The key starts after the header and two version fields
			let key_start = 6 + 6 + 6 + 4;
			let signature_start = encoded.len() - SIGNATURE_SIZE;
			let covered: Vec<usize> = (key_start..key_start + 32).chain(signature_start..encoded.len()).collect();
			encoded[covered[index.index(covered.len())]] ^= flip;
			prop_assert!(Metadata::decode_body(&encoded[6..], b"").is_err());
		}
	}
}
