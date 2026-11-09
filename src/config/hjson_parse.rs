//! Parses Hjson (and so JSON) the way hjson-go does.
//!
//! Ported from hjson-go, MIT License, Copyright (c) 2016, 2017 Christian Zangl.
//! See THIRD-PARTY-NOTICES.

use std::fmt;

/// A parsed value. Unquoted scalars keep their text, because hjson-go reads
/// them as strings when the destination is a string (`Password: 12`).
#[derive(Clone, Debug, PartialEq)]
pub enum Hjson {
	Null,
	Bool(bool),
	/// The number's text, as Go's `json.Number`.
	Number(String),
	String(String),
	/// An unquoted value and what it means outside a string field.
	Bare(String, Box<Hjson>),
	Array(Vec<Hjson>),
	Object(Vec<(String, Hjson)>),
}

impl Hjson {
	/// The value as a non-string destination sees it.
	pub fn resolved(&self) -> &Hjson {
		match self {
			Hjson::Bare(_, value) => value,
			other => other,
		}
	}

	/// The text a string destination sees, if any.
	pub fn as_text(&self) -> Option<&str> {
		match self {
			Hjson::String(text) | Hjson::Bare(text, _) => Some(text),
			_ => None,
		}
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError(String);

impl fmt::Display for ParseError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

const MAX_NESTING_DEPTH: usize = 10000;

struct Parser<'a> {
	data: &'a [u8],
	/// One past the current character, as in hjson-go.
	at: usize,
	ch: u8,
	depth: usize,
}

fn is_punctuator(c: u8) -> bool {
	matches!(c, b'{' | b'}' | b'[' | b']' | b',' | b':')
}

impl Parser<'_> {
	fn next(&mut self) -> bool {
		if self.at < self.data.len() {
			self.ch = self.data[self.at];
			self.at += 1;
			true
		} else {
			self.at += 1;
			self.ch = 0;
			false
		}
	}

	fn prev(&mut self) -> bool {
		if self.at > 1 {
			self.ch = self.data[self.at - 2];
			self.at -= 1;
			true
		} else {
			false
		}
	}

	fn peek(&self, offset: isize) -> u8 {
		let pos = self.at as isize + offset;
		if pos >= 0 && (pos as usize) < self.data.len() {
			self.data[pos as usize]
		} else {
			0
		}
	}

	fn reset(&mut self) {
		self.at = 0;
		self.depth = 0;
		self.next();
	}

	fn error(&self, message: &str) -> ParseError {
		if self.at > self.data.len() || self.at == 0 {
			return ParseError(message.into());
		}
		let mut col = 0;
		let mut line = 1;
		let mut i = self.at - 1;
		while i > 0 && self.data[i] != b'\n' {
			col += 1;
			i -= 1;
		}
		while i > 0 {
			if self.data[i] == b'\n' {
				line += 1;
			}
			i -= 1;
		}
		let start = self.at - col;
		let end = (start + 20).min(self.data.len());
		ParseError(format!(
			"{message} at line {line},{col} >>> {}",
			String::from_utf8_lossy(&self.data[start..end])
		))
	}

	fn white(&mut self) {
		while self.ch > 0 {
			while self.ch > 0 && self.ch <= b' ' {
				self.next();
			}
			if self.ch == b'#' || (self.ch == b'/' && self.peek(0) == b'/') {
				while self.ch > 0 && self.ch != b'\n' {
					self.next();
				}
			} else if self.ch == b'/' && self.peek(0) == b'*' {
				self.next();
				self.next();
				while self.ch > 0 && !(self.ch == b'*' && self.peek(0) == b'/') {
					self.next();
				}
				if self.ch > 0 {
					self.next();
					self.next();
				}
			} else {
				break;
			}
		}
	}

	fn read_string(&mut self, allow_multiline: bool) -> Result<String, ParseError> {
		let mut out = Vec::new();
		let exit = self.ch;
		while self.next() {
			if self.ch == exit {
				self.next();
				if allow_multiline && exit == b'\'' && self.ch == b'\'' && out.is_empty() {
					self.next();
					return self.read_multiline_string();
				}
				return Ok(String::from_utf8_lossy(&out).into_owned());
			}
			if self.ch == b'\\' {
				self.next();
				match self.ch {
					b'u' => {
						let mut code = 0u32;
						for _ in 0..4 {
							self.next();
							let digit = (self.ch as char).to_digit(16).ok_or_else(|| {
								self.error(&format!("Bad \\u char {}", self.ch as char))
							})?;
							code = code * 16 + digit;
						}
						let c = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
						out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
					}
					b'"' | b'\'' | b'\\' | b'/' => out.push(self.ch),
					b'b' => out.push(8),
					b'f' => out.push(12),
					b'n' => out.push(b'\n'),
					b'r' => out.push(b'\r'),
					b't' => out.push(b'\t'),
					other => return Err(self.error(&format!("Bad escape \\{}", other as char))),
				}
			} else if self.ch == b'\n' || self.ch == b'\r' {
				return Err(self.error("Bad string containing newline"));
			} else {
				out.push(self.ch);
			}
		}
		Err(self.error("Bad string"))
	}

	fn read_multiline_string(&mut self) -> Result<String, ParseError> {
		let mut out = Vec::new();
		let mut triple = 0;
		let mut indent = 0isize;
		loop {
			let c = self.peek(-indent - 5);
			if c == 0 || c == b'\n' {
				break;
			}
			indent += 1;
		}
		let skip_indent = |parser: &mut Self| {
			let mut skip = indent;
			while parser.ch > 0 && parser.ch <= b' ' && parser.ch != b'\n' && skip > 0 {
				skip -= 1;
				parser.next();
			}
		};
		while self.ch > 0 && self.ch <= b' ' && self.ch != b'\n' {
			self.next();
		}
		if self.ch == b'\n' {
			self.next();
			skip_indent(self);
		}
		let mut last_lf = false;
		loop {
			if self.ch == 0 {
				return Err(self.error("Bad multiline string"));
			} else if self.ch == b'\'' {
				triple += 1;
				self.next();
				if triple == 3 {
					if last_lf {
						out.pop();
					}
					return Ok(String::from_utf8_lossy(&out).into_owned());
				}
				continue;
			}
			while triple > 0 {
				out.push(b'\'');
				triple -= 1;
				last_lf = false;
			}
			if self.ch == b'\n' {
				out.push(b'\n');
				last_lf = true;
				self.next();
				skip_indent(self);
			} else {
				if self.ch != b'\r' {
					out.push(self.ch);
					last_lf = false;
				}
				self.next();
			}
		}
	}

	fn read_key_name(&mut self) -> Result<String, ParseError> {
		if self.ch == b'"' || self.ch == b'\'' {
			return self.read_string(false);
		}
		let mut name = Vec::new();
		let start = self.at;
		let mut space: Option<usize> = None;
		loop {
			if self.ch == b':' {
				if name.is_empty() {
					return Err(
						self.error("Found ':' but no key name (for an empty key name use quotes)")
					);
				}
				if let Some(space) = space.filter(|space| *space != name.len()) {
					self.at = start + space;
					return Err(
						self.error("Found whitespace in your key name (use quotes to include)")
					);
				}
				return Ok(String::from_utf8_lossy(&name).into_owned());
			} else if self.ch <= b' ' {
				if self.ch == 0 {
					return Err(
						self.error("Found EOF while looking for a key name (check your syntax)")
					);
				}
				space.get_or_insert(name.len());
			} else {
				if is_punctuator(self.ch) {
					return Err(self.error(&format!(
						"Found '{}' where a key name was expected (check your syntax or use quotes if the key name includes {{}}[],: or whitespace)",
						self.ch as char
					)));
				}
				name.push(self.ch);
			}
			self.next();
		}
	}

	/// An unquoted value: a keyword, a number, or a string to the end of the line.
	fn read_bare(&mut self) -> Result<Hjson, ParseError> {
		if is_punctuator(self.ch) {
			return Err(self.error(&format!(
				"Found a punctuator character '{}' when expecting a quoteless string (check your syntax)",
				self.ch as char
			)));
		}
		let first = self.ch;
		let mut value = vec![self.ch];
		loop {
			self.next();
			let is_eol = matches!(self.ch, b'\r' | b'\n' | 0);
			let at_end = is_eol
				|| matches!(self.ch, b',' | b'}' | b']' | b'#')
				|| (self.ch == b'/' && matches!(self.peek(0), b'/' | b'*'));
			if at_end {
				let text = String::from_utf8_lossy(&value);
				let trimmed = text.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\u{b}');
				let interpreted = match first {
					b'f' if trimmed == "false" => Some(Hjson::Bool(false)),
					b'n' if trimmed == "null" => Some(Hjson::Null),
					b't' if trimmed == "true" => Some(Hjson::Bool(true)),
					b'-' | b'0'..=b'9' => parse_number(&value).map(Hjson::Number),
					_ => None,
				};
				if let Some(interpreted) = interpreted {
					return Ok(Hjson::Bare(trimmed.to_string(), Box::new(interpreted)));
				}
				if is_eol {
					return Ok(Hjson::Bare(
						trimmed.to_string(),
						Box::new(Hjson::String(trimmed.to_string())),
					));
				}
			}
			value.push(self.ch);
		}
	}

	fn read_value(&mut self) -> Result<Hjson, ParseError> {
		self.white();
		match self.ch {
			b'{' => {
				self.depth += 1;
				let value = self.read_object(false);
				self.depth -= 1;
				value
			}
			b'[' => {
				self.depth += 1;
				let value = self.read_array();
				self.depth -= 1;
				value
			}
			b'"' | b'\'' => self.read_string(true).map(Hjson::String),
			_ => {
				let value = self.read_bare()?;
				if self.ch == b'#' || self.ch == b'/' {
					while self.prev() && self.ch <= b' ' {}
					self.next();
				}
				Ok(value)
			}
		}
	}

	fn read_array(&mut self) -> Result<Hjson, ParseError> {
		if self.depth > MAX_NESTING_DEPTH {
			return Err(self.error(&format!("Exceeded max depth ({MAX_NESTING_DEPTH})")));
		}
		let mut items = Vec::new();
		self.next();
		self.white();
		if self.ch == b']' {
			self.next();
			return Ok(Hjson::Array(items));
		}
		while self.ch > 0 {
			items.push(self.read_value()?);
			self.white();
			if self.ch == b',' {
				self.next();
				self.white();
			}
			if self.ch == b']' {
				self.next();
				return Ok(Hjson::Array(items));
			}
			self.white();
		}
		Err(self.error("End of input while parsing an array (did you forget a closing ']'?)"))
	}

	fn read_object(&mut self, without_braces: bool) -> Result<Hjson, ParseError> {
		if self.depth > MAX_NESTING_DEPTH {
			return Err(self.error(&format!("Exceeded max depth ({MAX_NESTING_DEPTH})")));
		}
		let mut fields: Vec<(String, Hjson)> = Vec::new();
		if !without_braces {
			self.next();
		}
		self.white();
		if !without_braces && self.ch == b'}' {
			self.next();
			return Ok(Hjson::Object(fields));
		}
		while self.ch > 0 {
			let key = self.read_key_name()?;
			self.white();
			if self.ch != b':' {
				return Err(self.error(&format!("Expected ':' instead of '{}'", self.ch as char)));
			}
			self.next();
			let value = self.read_value()?;
			// A later duplicate replaces the earlier value in place, as in an ordered map
			match fields.iter_mut().find(|(name, _)| *name == key) {
				Some(field) => field.1 = value,
				None => fields.push((key, value)),
			}
			self.white();
			if self.ch == b',' {
				self.next();
				self.white();
			}
			if self.ch == b'}' && !without_braces {
				self.next();
				return Ok(Hjson::Object(fields));
			}
			self.white();
		}
		if without_braces {
			Ok(Hjson::Object(fields))
		} else {
			Err(self.error("End of input while parsing an object (did you forget a closing '}'?)"))
		}
	}

	fn check_trailing(&mut self) -> Result<(), ParseError> {
		self.white();
		if self.ch > 0 {
			return Err(self.error("Syntax error, found trailing characters"));
		}
		Ok(())
	}
}

/// The text of a number, if all of `text` (ignoring trailing whitespace) is one.
fn parse_number(text: &[u8]) -> Option<String> {
	let at = |pos: usize| text.get(pos).copied().unwrap_or(0);
	let mut pos = 0;
	let mut leading_zeros: i32 = 0;
	let mut test_leading = true;
	if at(pos) == b'-' {
		pos += 1;
	}
	while at(pos).is_ascii_digit() {
		if test_leading {
			if at(pos) == b'0' {
				leading_zeros += 1;
			} else {
				test_leading = false;
			}
		}
		pos += 1;
	}
	if test_leading {
		leading_zeros -= 1;
	}
	if at(pos) == b'.' {
		pos += 1;
		while at(pos).is_ascii_digit() {
			pos += 1;
		}
	}
	if matches!(at(pos), b'e' | b'E') {
		pos += 1;
		if matches!(at(pos), b'-' | b'+') {
			pos += 1;
		}
		if !at(pos).is_ascii_digit() {
			return None;
		}
		while at(pos).is_ascii_digit() {
			pos += 1;
		}
	}
	let end = pos;
	while at(pos) > 0 && at(pos) <= b' ' {
		pos += 1;
	}
	if at(pos) > 0 || leading_zeros != 0 {
		return None;
	}
	Some(String::from_utf8_lossy(&text[..end]).into_owned())
}

/// Parses a document: an object with or without braces, or any other value.
pub fn parse(text: &str) -> Result<Hjson, ParseError> {
	let mut parser = Parser {
		data: text.as_bytes(),
		at: 0,
		ch: b' ',
		depth: 0,
	};
	parser.reset();
	parser.white();
	match parser.ch {
		b'{' | b'[' => {
			let value = parser.read_value()?;
			parser.check_trailing()?;
			return Ok(value);
		}
		_ => {}
	}
	let braceless = parser.read_object(true).and_then(|value| {
		parser.check_trailing()?;
		Ok(value)
	});
	if let Ok(value) = braceless {
		return Ok(value);
	}
	parser.reset();
	let value = parser.read_value()?;
	parser.check_trailing()?;
	Ok(value)
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	fn bare(text: &str, value: Hjson) -> Hjson {
		Hjson::Bare(text.into(), Box::new(value))
	}

	#[test]
	fn parses_quoteless_values() {
		let parsed = parse(
			"{\n  a: 2601f2ab\n\n  # c\n  b: 12 \n  c: true\n  d: tcp://x:1 # not a comment\n}",
		)
		.unwrap();
		assert_eq!(
			parsed,
			Hjson::Object(vec![
				(
					"a".into(),
					bare("2601f2ab", Hjson::String("2601f2ab".into()))
				),
				("b".into(), bare("12", Hjson::Number("12".into()))),
				("c".into(), bare("true", Hjson::Bool(true))),
				(
					"d".into(),
					bare(
						"tcp://x:1 # not a comment",
						Hjson::String("tcp://x:1 # not a comment".into())
					)
				),
			])
		);
	}

	#[test]
	fn parses_json_and_braceless_roots() {
		assert_eq!(
			parse(r#"{"a": [1, "x"], "b": {}}"#).unwrap(),
			Hjson::Object(vec![
				(
					"a".into(),
					Hjson::Array(vec![
						bare("1", Hjson::Number("1".into())),
						Hjson::String("x".into())
					])
				),
				("b".into(), Hjson::Object(vec![])),
			])
		);
		assert_eq!(
			parse("a: 1\nb: x").unwrap(),
			Hjson::Object(vec![
				("a".into(), bare("1", Hjson::Number("1".into()))),
				("b".into(), bare("x", Hjson::String("x".into()))),
			])
		);
	}

	#[test]
	fn parses_multiline_strings() {
		assert_eq!(
			parse("{\n  v:\n    '''\n    a\n    b\n    '''\n}").unwrap(),
			Hjson::Object(vec![("v".into(), Hjson::String("a\nb".into()))])
		);
	}

	#[test]
	fn rejects_bad_syntax() {
		for text in ["{a: [1", "{a b: 1}", "{\"a\": \"b\nc\"}", "{a: 1}}"] {
			assert!(parse(text).is_err(), "{text}");
		}
	}

	proptest! {
		#[test]
		fn never_panics(text in ".{0,64}") {
			let _ = parse(&text);
		}
	}
}
