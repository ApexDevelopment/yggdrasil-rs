//! Builds ICMPv6 messages to hand back to the local host.

use std::net::Ipv6Addr;

pub const IPV6_HEADER_LEN: usize = 40;
const NEXT_HEADER_ICMPV6: u8 = 58;
pub const ICMPV6_PACKET_TOO_BIG: u8 = 2;

/// The internet checksum of the ICMPv6 message `message` between `src` and `dst`.
fn checksum(src: &Ipv6Addr, dst: &Ipv6Addr, message: &[u8]) -> u16 {
	let mut sum: u32 = 0;
	let mut add = |bytes: &[u8]| {
		for chunk in bytes.chunks(2) {
			let word = match chunk {
				[high, low] => u16::from_be_bytes([*high, *low]),
				[high] => u16::from_be_bytes([*high, 0]),
				_ => unreachable!(),
			};
			sum += u32::from(word);
		}
	};
	add(&src.octets());
	add(&dst.octets());
	add(&(message.len() as u32).to_be_bytes());
	add(&[0, 0, 0, NEXT_HEADER_ICMPV6]);
	add(message);
	while sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	!(sum as u16)
}

/// An IPv6 packet carrying an ICMPv6 message with the given type, code and body.
pub fn create_icmpv6(
	dst: Ipv6Addr,
	src: Ipv6Addr,
	message_type: u8,
	code: u8,
	body: &[u8],
) -> Vec<u8> {
	let mut message = Vec::with_capacity(4 + body.len());
	message.extend_from_slice(&[message_type, code, 0, 0]);
	message.extend_from_slice(body);
	let sum = checksum(&src, &dst, &message);
	message[2..4].copy_from_slice(&sum.to_be_bytes());

	let mut packet = Vec::with_capacity(IPV6_HEADER_LEN + message.len());
	packet.extend_from_slice(&[0x60, 0, 0, 0]);
	packet.extend_from_slice(&(message.len() as u16).to_be_bytes());
	packet.push(NEXT_HEADER_ICMPV6);
	packet.push(255);
	packet.extend_from_slice(&src.octets());
	packet.extend_from_slice(&dst.octets());
	packet.extend_from_slice(&message);
	packet
}

/// A "packet too big" message telling the sender of `original` to use `mtu`.
pub fn packet_too_big(original: &[u8], mtu: u32) -> Option<Vec<u8>> {
	// Quote at most 512 bytes, as Go does
	let quoted = &original[..original.len().min(512)];
	if quoted.len() < IPV6_HEADER_LEN {
		return None;
	}
	let src: [u8; 16] = quoted[8..24].try_into().ok()?;
	let dst: [u8; 16] = quoted[24..40].try_into().ok()?;
	let mut body = mtu.to_be_bytes().to_vec();
	body.extend_from_slice(quoted);
	Some(create_icmpv6(
		Ipv6Addr::from(src),
		Ipv6Addr::from(dst),
		ICMPV6_PACKET_TOO_BIG,
		0,
		&body,
	))
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn checksums_verify(src in any::<[u8; 16]>(), dst in any::<[u8; 16]>(), body in proptest::collection::vec(any::<u8>(), 0..600)) {
			let packet = create_icmpv6(Ipv6Addr::from(dst), Ipv6Addr::from(src), 1, 4, &body);
			prop_assert_eq!(packet.len(), IPV6_HEADER_LEN + 4 + body.len());
			// Summing a message that includes its own checksum gives zero
			prop_assert_eq!(checksum(&Ipv6Addr::from(src), &Ipv6Addr::from(dst), &packet[IPV6_HEADER_LEN..]), 0);
		}
	}
}
