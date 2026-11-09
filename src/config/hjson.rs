//! Writes Hjson the way hjson-go's `Marshal` does with its default options.
//!
//! Ported from hjson-go, MIT License, Copyright (c) 2016, 2017 Christian Zangl.
//! See THIRD-PARTY-NOTICES.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Number, Value};

const COMMON_RANGE: &str = r"\x7f-\x9f\x{00ad}\x{0600}-\x{0604}\x{070f}\x{17b4}\x{17b5}\x{200c}-\x{200f}\x{2028}-\x{202f}\x{2060}-\x{206f}\x{feff}\x{fff0}-\x{ffff}";
/// Go's RE2 `\s`, which unlike Rust's is ASCII only.
const SPACE: &str = r"[\t\n\x0c\r ]";

static NEEDS_ESCAPE: LazyLock<Regex> =
	LazyLock::new(|| Regex::new(&format!(r#"[\\"\x00-\x1f{COMMON_RANGE}]"#)).expect("valid regex"));
static NEEDS_QUOTES: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(&format!(
		r#"^{SPACE}|^"|^'|^#|^/\*|^//|^\{{|^\}}|^\[|^\]|^:|^,|{SPACE}$|[\x00-\x1f{COMMON_RANGE}]"#
	))
	.expect("valid regex")
});
static NEEDS_ESCAPE_ML: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(&format!(
		r"'''|^{SPACE}+$|[\x00-\x08\x0b-\x1f{COMMON_RANGE}]"
	))
	.expect("valid regex")
});
static STARTS_WITH_KEYWORD: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(&format!(
		r"^(true|false|null){SPACE}*((,|\]|\}}|#|//|/\*)(?s:.*))?$"
	))
	.expect("valid regex")
});
static NEEDS_ESCAPE_NAME: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(&format!(r#"[,\{{\[\}}\]{SPACE}:#"']|//|/\*"#)).expect("valid regex")
});

/// A field of the root object, with the comment written above it.
pub struct Field<'a> {
	pub name: &'a str,
	pub comment: &'a str,
	pub value: Value,
}

struct Writer {
	out: String,
	indent: usize,
}

impl Writer {
	fn write_indent(&mut self, indent: usize) {
		self.out.push('\n');
		self.write_indent_no_eol(indent);
	}

	fn write_indent_no_eol(&mut self, indent: usize) {
		for _ in 0..indent {
			self.out.push_str("  ");
		}
	}

	fn fields<'a>(
		&mut self,
		separator: &str,
		fields: impl ExactSizeIterator<Item = (&'a str, &'a str, &'a Value)>,
	) {
		let count = fields.len();
		self.out.push_str(separator);
		self.out.push('{');
		if count == 0 {
			self.out.push('}');
			return;
		}
		let outer = self.indent;
		self.indent += 1;
		for (i, (name, comment, value)) in fields.enumerate() {
			self.out.push('\n');
			if !comment.is_empty() {
				for line in comment.split('\n') {
					self.write_indent_no_eol(self.indent);
					self.out.push_str(&format!("# {line}\n"));
				}
			}
			self.write_indent_no_eol(self.indent);
			self.out.push_str(&quote_name(name));
			self.out.push(':');
			self.value(value, " ", true);
			if !comment.is_empty() && i < count - 1 {
				self.out.push('\n');
			}
		}
		self.write_indent(outer);
		self.out.push('}');
		self.indent = outer;
	}

	fn value(&mut self, value: &Value, separator: &str, is_obj_element: bool) {
		let separator = if is_obj_element { separator } else { "" };
		match value {
			Value::Null => {
				self.out.push_str(separator);
				self.out.push_str("null");
			}
			Value::Bool(b) => {
				self.out.push_str(separator);
				self.out.push_str(if *b { "true" } else { "false" });
			}
			Value::Number(n) => {
				self.out.push_str(separator);
				self.out.push_str(&format_number(n));
			}
			Value::String(s) => self.quote(s, separator),
			Value::Array(items) => {
				self.out.push_str(separator);
				self.out.push('[');
				if items.is_empty() {
					self.out.push(']');
					return;
				}
				let outer = self.indent;
				self.indent += 1;
				for item in items {
					self.write_indent(self.indent);
					self.value(item, "", false);
				}
				self.write_indent(outer);
				self.out.push(']');
				self.indent = outer;
			}
			// Callers sort Go maps; Go structs keep their field order
			Value::Object(map) => self.fields(
				separator,
				map.iter().map(|(name, value)| (name.as_str(), "", value)),
			),
		}
	}

	fn quote(&mut self, value: &str, separator: &str) {
		if value.is_empty() {
			self.out.push_str(separator);
			self.out.push_str("\"\"");
		} else if NEEDS_QUOTES.is_match(value)
			|| starts_with_number(value.as_bytes())
			|| STARTS_WITH_KEYWORD.is_match(value)
		{
			if !NEEDS_ESCAPE.is_match(value) {
				self.out.push_str(&format!("{separator}\"{value}\""));
			} else if !NEEDS_ESCAPE_ML.is_match(value) {
				self.multiline(value, separator);
			} else {
				self.out
					.push_str(&format!("{separator}\"{}\"", escape(value)));
			}
		} else {
			self.out.push_str(separator);
			self.out.push_str(value);
		}
	}

	fn multiline(&mut self, value: &str, separator: &str) {
		let lines: Vec<&str> = value.split('\n').collect();
		if let [line] = lines[..] {
			self.out.push_str(&format!("{separator}'''{line}'''"));
			return;
		}
		self.write_indent(self.indent + 1);
		self.out.push_str("'''");
		for line in lines {
			self.write_indent(if line.is_empty() { 0 } else { self.indent + 1 });
			self.out.push_str(line);
		}
		self.write_indent(self.indent + 1);
		self.out.push_str("'''");
	}
}

fn escape(text: &str) -> String {
	NEEDS_ESCAPE
		.replace_all(text, |captures: &regex::Captures| {
			let c = captures[0].chars().next().expect("one character");
			match c {
				'\u{8}' => "\\b".to_string(),
				'\t' => "\\t".to_string(),
				'\n' => "\\n".to_string(),
				'\u{c}' => "\\f".to_string(),
				'\r' => "\\r".to_string(),
				'"' => "\\\"".to_string(),
				'\\' => "\\\\".to_string(),
				c => format!("\\u{:04x}", c as u32),
			}
		})
		.into_owned()
}

fn quote_name(name: &str) -> String {
	if name.is_empty() {
		"\"\"".into()
	} else if NEEDS_ESCAPE_NAME.is_match(name) || NEEDS_ESCAPE.is_match(name) {
		format!("\"{}\"", escape(name))
	} else {
		name.into()
	}
}

/// Whether hjson would read the start of `text` as a number, so it must be quoted.
fn starts_with_number(text: &[u8]) -> bool {
	let at = |pos: usize| text.get(pos).copied().unwrap_or(0);
	let mut pos = 0;
	let mut ch = at(pos);
	let mut leading_zeros: i32 = 0;
	let mut test_leading = true;
	let advance = |pos: &mut usize| {
		*pos += 1;
		at(*pos)
	};
	if ch == b'-' {
		ch = advance(&mut pos);
	}
	while ch.is_ascii_digit() {
		if test_leading {
			if ch == b'0' {
				leading_zeros += 1;
			} else {
				test_leading = false;
			}
		}
		ch = advance(&mut pos);
	}
	if test_leading {
		leading_zeros -= 1;
	}
	if ch == b'.' {
		loop {
			ch = advance(&mut pos);
			if !ch.is_ascii_digit() {
				break;
			}
		}
	}
	if ch == b'e' || ch == b'E' {
		ch = advance(&mut pos);
		if ch == b'-' || ch == b'+' {
			ch = advance(&mut pos);
		}
		if !ch.is_ascii_digit() {
			return false;
		}
		while ch.is_ascii_digit() {
			ch = advance(&mut pos);
		}
	}
	while ch > 0 && ch <= b' ' {
		ch = advance(&mut pos);
	}
	let next = at(pos + 1);
	if matches!(ch, b',' | b'}' | b']' | b'#') || (ch == b'/' && (next == b'/' || next == b'*')) {
		ch = 0;
	}
	ch == 0 && leading_zeros == 0
}

/// The shorter of Go's 'f' and 'E' formats, lowercased.
fn format_number(n: &Number) -> String {
	let Some(f) = n.as_f64().filter(|_| n.is_f64()) else {
		return n.to_string();
	};
	if !f.is_finite() {
		return "null".into();
	}
	if f == 0.0 {
		return "0".into();
	}
	let fixed = format!("{f}");
	let formatted = format!("{f:e}");
	let (mantissa, exponent) = formatted.split_once('e').expect("exponent");
	let exponent: i32 = exponent.parse().expect("integer exponent");
	let sign = if exponent < 0 { '-' } else { '+' };
	let scientific = format!("{mantissa}e{sign}{:02}", exponent.abs());
	if scientific.len() < fixed.len() {
		scientific
	} else {
		fixed
	}
}

/// Writes a root object with a comment above each field.
pub fn to_string(fields: &[Field<'_>]) -> String {
	let mut writer = Writer {
		out: String::new(),
		indent: 0,
	};
	writer.fields(
		"",
		fields
			.iter()
			.map(|field| (field.name, field.comment, &field.value)),
	);
	writer.out
}

#[cfg(test)]
mod tests {
	use super::*;
	use serde_json::json;

	fn render(value: Value) -> String {
		to_string(&[Field {
			name: "v",
			comment: "",
			value,
		}])
	}

	#[test]
	fn quotes_ambiguous_strings() {
		assert_eq!(render(json!("tcp://a:1")), "{\n  v: tcp://a:1\n}");
		assert_eq!(render(json!("true")), "{\n  v: \"true\"\n}");
		assert_eq!(render(json!("12")), "{\n  v: \"12\"\n}");
		assert_eq!(render(json!("12a")), "{\n  v: 12a\n}");
		assert_eq!(render(json!(" x")), "{\n  v: \" x\"\n}");
		assert_eq!(render(json!("#x")), "{\n  v: \"#x\"\n}");
		assert_eq!(render(json!("")), "{\n  v: \"\"\n}");
		assert_eq!(render(json!("a\u{1}b")), "{\n  v: \"a\\u0001b\"\n}");
	}

	#[test]
	fn writes_multiline_strings() {
		assert_eq!(
			render(json!("a\nb")),
			"{\n  v:\n    '''\n    a\n    b\n    '''\n}"
		);
	}

	#[test]
	fn formats_numbers_like_hjson_go() {
		assert_eq!(render(json!(1e21)), "{\n  v: 1e+21\n}");
		assert_eq!(render(json!(0.000001)), "{\n  v: 1e-06\n}");
		assert_eq!(render(json!(1.0)), "{\n  v: 1\n}");
		assert_eq!(
			render(json!(12345678901234567890.0)),
			"{\n  v: 12345678901234567000\n}"
		);
	}

	#[test]
	fn nests_objects_and_arrays() {
		assert_eq!(
			render(json!([{"b": 1, "a": []}, {}])),
			"{\n  v: [\n    {\n      b: 1\n      a: []\n    }\n    {}\n  ]\n}"
		);
	}
}
