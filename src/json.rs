//! JSON output that matches Go's `encoding/json` byte for byte: struct fields
//! keep their order, floats are formatted like Go's, and `<`, `>` and `&` are escaped.

use serde::Serialize;
use serde_json::{Number, Value};

/// Like Go's `json.Marshal`.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
	let mut out = String::new();
	write_value(&mut out, &serde_json::to_value(value)?, None, 0);
	Ok(out)
}

/// Like Go's `json.MarshalIndent(value, "", "  ")`.
pub fn to_string_pretty<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
	let mut out = String::new();
	write_value(&mut out, &serde_json::to_value(value)?, Some("  "), 0);
	Ok(out)
}

fn newline(out: &mut String, indent: Option<&str>, depth: usize) {
	if let Some(unit) = indent {
		out.push('\n');
		for _ in 0..depth {
			out.push_str(unit);
		}
	}
}

fn write_value(out: &mut String, value: &Value, indent: Option<&str>, depth: usize) {
	match value {
		Value::Null => out.push_str("null"),
		Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
		Value::Number(n) => out.push_str(&format_number(n)),
		Value::String(s) => write_string(out, s),
		Value::Array(items) if items.is_empty() => out.push_str("[]"),
		Value::Array(items) => {
			out.push('[');
			for (i, item) in items.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				newline(out, indent, depth + 1);
				write_value(out, item, indent, depth + 1);
			}
			newline(out, indent, depth);
			out.push(']');
		}
		Value::Object(map) if map.is_empty() => out.push_str("{}"),
		Value::Object(map) => {
			out.push('{');
			for (i, (key, item)) in map.iter().enumerate() {
				if i > 0 {
					out.push(',');
				}
				newline(out, indent, depth + 1);
				write_string(out, key);
				out.push(':');
				if indent.is_some() {
					out.push(' ');
				}
				write_value(out, item, indent, depth + 1);
			}
			newline(out, indent, depth);
			out.push('}');
		}
	}
}

fn format_number(n: &Number) -> String {
	match n.as_f64() {
		Some(f) if n.is_f64() => format_float(f),
		_ => n.to_string(),
	}
}

/// Formats a float the way Go's `encoding/json` does.
pub fn format_float(f: f64) -> String {
	if !f.is_finite() {
		return "null".into();
	}
	let abs = f.abs();
	if abs != 0.0 && !(1e-6..1e21).contains(&abs) {
		// Go's 'e' format, but with single-digit negative exponents unpadded
		let formatted = format!("{f:e}");
		let (mantissa, exponent) = formatted.split_once('e').expect("exponent");
		let exponent: i32 = exponent.parse().expect("integer exponent");
		if exponent < 0 {
			format!("{mantissa}e-{}", -exponent)
		} else {
			format!("{mantissa}e+{exponent:02}")
		}
	} else {
		format!("{f}")
	}
}

/// Writes a quoted string with Go's escaping rules.
pub fn write_string(out: &mut String, s: &str) {
	out.push('"');
	for c in s.chars() {
		match c {
			'"' => out.push_str("\\\""),
			'\\' => out.push_str("\\\\"),
			'\n' => out.push_str("\\n"),
			'\r' => out.push_str("\\r"),
			'\t' => out.push_str("\\t"),
			'\u{8}' => out.push_str("\\b"),
			'\u{c}' => out.push_str("\\f"),
			'<' | '>' | '&' | '\u{2028}' | '\u{2029}' => {
				out.push_str(&format!("\\u{:04x}", c as u32));
			}
			c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
			c => out.push(c),
		}
	}
	out.push('"');
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	#[test]
	fn escapes_like_go() {
		assert_eq!(
			to_string(&json!({"a<b": "c&d>\u{1}\n"})).unwrap(),
			r#"{"a\u003cb":"c\u0026d\u003e\u0001\n"}"#
		);
	}

	#[test]
	fn formats_floats_like_go() {
		for (value, expected) in [
			(1.0, "1"),
			(1e21, "1e+21"),
			(0.000001, "0.000001"),
			(1.5e-7, "1.5e-7"),
			(1.5e-10, "1.5e-10"),
			(12345678901234567890.0, "12345678901234567000"),
			(-2.5, "-2.5"),
			(0.0, "0"),
		] {
			assert_eq!(format_float(value), expected);
		}
	}

	#[test]
	fn indents_like_go() {
		let value = json!({"b": [], "a": {}, "c": [1, {"d": true}]});
		assert_eq!(
			to_string_pretty(&value).unwrap(),
			"{\n  \"b\": [],\n  \"a\": {},\n  \"c\": [\n    1,\n    {\n      \"d\": true\n    }\n  ]\n}"
		);
	}
}
