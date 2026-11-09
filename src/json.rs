//! JSON output that matches Go's `encoding/json` byte for byte.

use serde::Serialize;

/// Escapes the characters Go escapes for safe embedding in HTML. They only
/// ever appear inside strings in serialized JSON, so replacing them is safe.
fn escape_like_go(json: String) -> String {
	if !json.contains(['<', '>', '&', '\u{2028}', '\u{2029}']) {
		return json;
	}
	let mut escaped = String::with_capacity(json.len() + 16);
	for c in json.chars() {
		match c {
			'<' => escaped.push_str("\\u003c"),
			'>' => escaped.push_str("\\u003e"),
			'&' => escaped.push_str("\\u0026"),
			'\u{2028}' => escaped.push_str("\\u2028"),
			'\u{2029}' => escaped.push_str("\\u2029"),
			c => escaped.push(c),
		}
	}
	escaped
}

/// Like Go's `json.Marshal`.
pub fn to_string<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
	serde_json::to_string(value).map(escape_like_go)
}

/// Like Go's `json.MarshalIndent(value, "", "  ")`.
pub fn to_string_pretty<T: Serialize + ?Sized>(value: &T) -> serde_json::Result<String> {
	serde_json::to_string_pretty(value).map(escape_like_go)
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn escapes_html_characters() {
		assert_eq!(
			to_string(&serde_json::json!({"a<b": "c&d>"})).unwrap(),
			r#"{"a<b":"c&d>"}"#
		);
	}
}
