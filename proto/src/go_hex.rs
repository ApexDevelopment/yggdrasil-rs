//! Hex decoding with the same error messages as Go's `encoding/hex`.
//!
//! Ported from Go's `encoding/hex`, BSD-3-Clause, Copyright 2009 The Go Authors.
//! See THIRD-PARTY-NOTICES.

fn value(byte: u8) -> Option<u8> {
	(byte as char).to_digit(16).map(|digit| digit as u8)
}

/// Go's `%#U` formatting of a byte read as a rune.
fn describe(byte: u8) -> String {
	let c = char::from(byte);
	let printable = matches!(byte, 0x21..=0x7e | 0xa1..=0xac | 0xae..=0xff) || byte == b' ';
	if printable {
		format!("U+{byte:04X} '{c}'")
	} else {
		format!("U+{byte:04X}")
	}
}

/// Like Go's `hex.DecodeString`.
pub fn decode(text: &str) -> Result<Vec<u8>, String> {
	let bytes = text.as_bytes();
	let invalid = |byte: u8| format!("encoding/hex: invalid byte: {}", describe(byte));
	let mut out = Vec::with_capacity(bytes.len() / 2);
	for pair in bytes.chunks(2) {
		let high = value(pair[0]).ok_or_else(|| invalid(pair[0]))?;
		let Some(&low) = pair.get(1) else {
			return Err("encoding/hex: odd length hex string".into());
		};
		out.push((high << 4) | value(low).ok_or_else(|| invalid(low))?);
	}
	Ok(out)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn reports_errors_like_go() {
		assert_eq!(decode("0aFf"), Ok(vec![0x0a, 0xff]));
		assert_eq!(
			decode("zz").unwrap_err(),
			"encoding/hex: invalid byte: U+007A 'z'"
		);
		assert_eq!(
			decode("abc").unwrap_err(),
			"encoding/hex: odd length hex string"
		);
		assert_eq!(
			decode("abz").unwrap_err(),
			"encoding/hex: invalid byte: U+007A 'z'"
		);
		assert_eq!(
			decode("a\u{1}").unwrap_err(),
			"encoding/hex: invalid byte: U+0001"
		);
	}
}
