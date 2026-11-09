//! Command-line flags with the syntax of Go's `flag` package: `-name`,
//! `--name`, `-name=value` and `-name value`, stopping at the first argument
//! that is not a flag.
//!
//! Parts are ported from Go's `flag` and `strconv` packages, BSD-3-Clause,
//! Copyright 2009 The Go Authors. See THIRD-PARTY-NOTICES.

use std::collections::HashMap;
use std::fmt::Write;

#[derive(Clone, Debug)]
enum Kind {
	Bool(bool),
	String(String),
	Int(i64),
}

#[derive(Clone, Debug)]
struct Flag {
	name: &'static str,
	usage: &'static str,
	kind: Kind,
}

#[derive(Clone, Debug, Default)]
pub struct Flags {
	flags: Vec<Flag>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
	/// `-h` or `-help` was given.
	Help,
	Invalid(String),
}

#[derive(Clone, Debug)]
pub struct Parsed {
	values: HashMap<&'static str, Kind>,
	/// The arguments after the flags.
	pub args: Vec<String>,
}

impl Parsed {
	pub fn bool(&self, name: &str) -> bool {
		matches!(self.values.get(name), Some(Kind::Bool(true)))
	}

	pub fn string(&self, name: &str) -> String {
		match self.values.get(name) {
			Some(Kind::String(value)) => value.clone(),
			_ => String::new(),
		}
	}

	pub fn int(&self, name: &str) -> i64 {
		match self.values.get(name) {
			Some(Kind::Int(value)) => *value,
			_ => 0,
		}
	}
}

impl Flags {
	pub fn bool(mut self, name: &'static str, default: bool, usage: &'static str) -> Self {
		self.flags.push(Flag {
			name,
			usage,
			kind: Kind::Bool(default),
		});
		self
	}

	pub fn string(mut self, name: &'static str, default: &str, usage: &'static str) -> Self {
		self.flags.push(Flag {
			name,
			usage,
			kind: Kind::String(default.into()),
		});
		self
	}

	pub fn int(mut self, name: &'static str, default: i64, usage: &'static str) -> Self {
		self.flags.push(Flag {
			name,
			usage,
			kind: Kind::Int(default),
		});
		self
	}

	pub fn parse(&self, args: impl IntoIterator<Item = String>) -> Result<Parsed, ParseError> {
		let mut values: HashMap<&'static str, Kind> = self
			.flags
			.iter()
			.map(|flag| (flag.name, flag.kind.clone()))
			.collect();
		let mut args = args.into_iter().peekable();
		while let Some(arg) = args.peek() {
			if arg.len() < 2 || !arg.starts_with('-') {
				break;
			}
			let arg = args.next().expect("peeked");
			let mut name = &arg[1..];
			if let Some(rest) = name.strip_prefix('-') {
				if rest.is_empty() {
					break;
				}
				name = rest;
			}
			if name.starts_with('-') || name.starts_with('=') {
				return Err(ParseError::Invalid(format!("bad flag syntax: {arg}")));
			}
			let (name, inline) = match name.split_once('=') {
				Some((name, value)) => (name, Some(value.to_string())),
				None => (name, None),
			};
			let Some(flag) = self.flags.iter().find(|flag| flag.name == name) else {
				if name == "help" || name == "h" {
					return Err(ParseError::Help);
				}
				return Err(ParseError::Invalid(format!(
					"flag provided but not defined: -{name}"
				)));
			};
			let value = match &flag.kind {
				Kind::Bool(_) => match inline.as_deref() {
					None => Kind::Bool(true),
					Some(text) => Kind::Bool(parse_go_bool(text).ok_or_else(|| {
						ParseError::Invalid(format!(
							"invalid boolean value {text:?} for -{name}: parse error"
						))
					})?),
				},
				kind => {
					let text = match inline {
						Some(text) => text,
						None => args.next().ok_or_else(|| {
							ParseError::Invalid(format!("flag needs an argument: -{name}"))
						})?,
					};
					match kind {
						Kind::Int(_) => Kind::Int(text.parse().map_err(|_| {
							ParseError::Invalid(format!(
								"invalid value {text:?} for flag -{name}: parse error"
							))
						})?),
						_ => Kind::String(text),
					}
				}
			};
			values.insert(flag.name, value);
		}
		Ok(Parsed {
			values,
			args: args.collect(),
		})
	}

	/// The flag descriptions, formatted like Go's `PrintDefaults`.
	pub fn defaults(&self) -> String {
		let mut flags = self.flags.clone();
		flags.sort_by_key(|flag| flag.name);
		let mut out = String::new();
		for flag in flags {
			let _ = write!(out, "  -{}", flag.name);
			let (type_name, usage) = unquote_usage(&flag);
			if !type_name.is_empty() {
				let _ = write!(out, " {type_name}");
			}
			if out.lines().last().is_some_and(|line| line.len() <= 4) {
				out.push('\t');
			} else {
				out.push_str("\n    \t");
			}
			out.push_str(&usage.replace('\n', "\n    \t"));
			match &flag.kind {
				Kind::Bool(true) => out.push_str(" (default true)"),
				Kind::String(default) if !default.is_empty() => {
					let _ = write!(out, " (default {default:?})");
				}
				Kind::Int(default) if *default != 0 => {
					let _ = write!(out, " (default {default})");
				}
				_ => {}
			}
			out.push('\n');
		}
		out
	}
}

/// Go takes a type name from back-quoted text in the usage, or uses the flag's type.
fn unquote_usage(flag: &Flag) -> (String, String) {
	if let Some(start) = flag.usage.find('`')
		&& let Some(len) = flag.usage[start + 1..].find('`')
	{
		let name = &flag.usage[start + 1..start + 1 + len];
		let usage = format!(
			"{}{}{}",
			&flag.usage[..start],
			name,
			&flag.usage[start + 2 + len..]
		);
		return (name.to_string(), usage);
	}
	let type_name = match flag.kind {
		Kind::Bool(_) => "",
		Kind::String(_) => "string",
		Kind::Int(_) => "int",
	};
	(type_name.to_string(), flag.usage.to_string())
}

fn parse_go_bool(text: &str) -> Option<bool> {
	match text {
		"1" | "t" | "T" | "true" | "TRUE" | "True" => Some(true),
		"0" | "f" | "F" | "false" | "FALSE" | "False" => Some(false),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn flags() -> Flags {
		Flags::default()
			.bool("json", false, "output JSON")
			.bool("borders", true, "draw borders")
			.string("endpoint", "unix:///x", "admin `address`")
			.int("fd", -1, "a file descriptor")
	}

	fn args(text: &str) -> Vec<String> {
		text.split_whitespace().map(str::to_string).collect()
	}

	#[test]
	fn parses_go_flag_syntax() {
		let parsed = flags()
			.parse(args(
				"-json --borders=false -endpoint tcp://a:1 -fd=3 getPeers sort=cost -json",
			))
			.unwrap();
		assert!(parsed.bool("json"));
		assert!(!parsed.bool("borders"));
		assert_eq!(parsed.string("endpoint"), "tcp://a:1");
		assert_eq!(parsed.int("fd"), 3);
		assert_eq!(parsed.args, args("getPeers sort=cost -json"));
	}

	#[test]
	fn keeps_defaults_and_stops_at_double_dash() {
		let parsed = flags().parse(args("-- -json")).unwrap();
		assert!(!parsed.bool("json"));
		assert!(parsed.bool("borders"));
		assert_eq!(parsed.int("fd"), -1);
		assert_eq!(parsed.args, args("-json"));
	}

	#[test]
	fn reports_errors() {
		assert_eq!(flags().parse(args("-help")).unwrap_err(), ParseError::Help);
		assert!(matches!(
			flags().parse(args("-nope")),
			Err(ParseError::Invalid(_))
		));
		assert!(matches!(
			flags().parse(args("-endpoint")),
			Err(ParseError::Invalid(_))
		));
		assert!(matches!(
			flags().parse(args("-fd=x")),
			Err(ParseError::Invalid(_))
		));
	}

	#[test]
	fn prints_defaults_like_go() {
		assert_eq!(
			flags().defaults(),
			"  -borders\n    \tdraw borders (default true)\n  -endpoint address\n    \tadmin address (default \"unix:///x\")\n  -fd int\n    \ta file descriptor (default -1)\n  -json\n    \toutput JSON\n"
		);
	}
}
