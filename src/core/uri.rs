//! Peering URIs like `tls://host:port?key=...` or `socks://proxy:1080/host:port`,
//! parsed the way Go's `net/url` parses them.

use std::fmt;
use std::time::Duration;

use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerUri {
	/// Always lowercase.
	pub scheme: String,
	/// Decoded `user[:password]`.
	pub user: Option<(String, Option<String>)>,
	/// Decoded `host[:port]`. IPv6 hosts keep their brackets and may carry a zone.
	pub host: String,
	/// Decoded path.
	pub path: String,
	/// Decoded query pairs, in order.
	pub query: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriError(pub String);

impl fmt::Display for UriError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for UriError {}

const USERINFO: &AsciiSet = &CONTROLS
	.add(b' ')
	.add(b'@')
	.add(b'/')
	.add(b'?')
	.add(b'#')
	.add(b':')
	.add(b'%');
const HOST: &AsciiSet = &CONTROLS.add(b' ').add(b'%').add(b'/').add(b'?').add(b'#');
const PATH: &AsciiSet = &CONTROLS.add(b' ').add(b'%').add(b'?').add(b'#');

fn decode(part: &str) -> Result<String, UriError> {
	percent_decode_str(part)
		.decode_utf8()
		.map(|decoded| decoded.into_owned())
		.map_err(|_| UriError(format!("invalid escape in {part:?}")))
}

impl PeerUri {
	pub fn parse(input: &str) -> Result<Self, UriError> {
		let input = input.split('#').next().unwrap_or_default();
		let (scheme, rest) = input
			.split_once("://")
			.ok_or_else(|| UriError(format!("missing scheme in {input:?}")))?;
		let valid_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
			&& scheme
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
		if !valid_scheme {
			return Err(UriError(format!("invalid scheme {scheme:?}")));
		}
		let (rest, raw_query) = match rest.split_once('?') {
			Some((rest, query)) => (rest, query),
			None => (rest, ""),
		};
		let (authority, raw_path) = match rest.find('/') {
			Some(idx) => rest.split_at(idx),
			None => (rest, ""),
		};
		let (user, raw_host) = match authority.rsplit_once('@') {
			Some((userinfo, host)) => {
				let user = match userinfo.split_once(':') {
					Some((name, password)) => (decode(name)?, Some(decode(password)?)),
					None => (decode(userinfo)?, None),
				};
				(Some(user), host)
			}
			None => (None, authority),
		};
		Ok(PeerUri {
			scheme: scheme.to_ascii_lowercase(),
			user,
			host: decode(raw_host)?,
			path: decode(raw_path)?,
			query: form_urlencoded::parse(raw_query.as_bytes())
				.map(|(key, value)| (key.into_owned(), value.into_owned()))
				.collect(),
		})
	}

	/// The first value for a query key, or `None` if the key is absent or empty.
	pub fn query_value(&self, key: &str) -> Option<&str> {
		self.query
			.iter()
			.find(|(name, _)| name == key)
			.map(|(_, value)| value.as_str())
			.filter(|value| !value.is_empty())
	}

	pub fn query_values<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a str> + 'a {
		self.query
			.iter()
			.filter(move |(name, _)| name == key)
			.map(|(_, value)| value.as_str())
	}

	/// This URI without its query, which identifies a link.
	pub fn without_query(&self) -> PeerUri {
		PeerUri {
			query: Vec::new(),
			..self.clone()
		}
	}

	/// Splits the host into a hostname (without brackets) and a port, like Go's `net.SplitHostPort`.
	pub fn host_port(&self) -> Result<(String, u16), UriError> {
		split_host_port(&self.host)
	}

	pub fn with_query(mut self, pairs: &[(&str, String)]) -> Self {
		self.query = pairs
			.iter()
			.map(|(key, value)| (key.to_string(), value.clone()))
			.collect();
		self
	}
}

pub fn split_host_port(hostport: &str) -> Result<(String, u16), UriError> {
	let missing_port = || UriError(format!("address {hostport}: missing port in address"));
	let (host, port) = if let Some(rest) = hostport.strip_prefix('[') {
		let (host, after) = rest
			.split_once(']')
			.ok_or_else(|| UriError(format!("address {hostport}: missing ']' in address")))?;
		let port = after.strip_prefix(':').ok_or_else(missing_port)?;
		(host, port)
	} else {
		let (host, port) = hostport.rsplit_once(':').ok_or_else(missing_port)?;
		if host.contains(':') {
			return Err(UriError(format!(
				"address {hostport}: too many colons in address"
			)));
		}
		(host, port)
	};
	let port = port
		.parse()
		.map_err(|_| UriError(format!("address {hostport}: invalid port")))?;
	Ok((host.to_string(), port))
}

/// Joins a host and port, bracketing IPv6 hosts, like Go's `net.JoinHostPort`.
pub fn join_host_port(host: &str, port: u16) -> String {
	if host.contains(':') {
		format!("[{host}]:{port}")
	} else {
		format!("{host}:{port}")
	}
}

impl fmt::Display for PeerUri {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}://", self.scheme)?;
		if let Some((name, password)) = &self.user {
			write!(f, "{}", utf8_percent_encode(name, USERINFO))?;
			if let Some(password) = password {
				write!(f, ":{}", utf8_percent_encode(password, USERINFO))?;
			}
			f.write_str("@")?;
		}
		write!(f, "{}", utf8_percent_encode(&self.host, HOST))?;
		write!(f, "{}", utf8_percent_encode(&self.path, PATH))?;
		if !self.query.is_empty() {
			let mut serializer = form_urlencoded::Serializer::new(String::new());
			for (key, value) in &self.query {
				serializer.append_pair(key, value);
			}
			write!(f, "?{}", serializer.finish())?;
		}
		Ok(())
	}
}

/// Parses a duration like `1h30m` or `2.5s`, accepting the same syntax as Go's `time.ParseDuration`.
pub fn parse_go_duration(input: &str) -> Option<Duration> {
	let (negative, mut rest) = match input.as_bytes().first()? {
		b'-' => (true, &input[1..]),
		b'+' => (false, &input[1..]),
		_ => (false, input),
	};
	if rest == "0" {
		return Some(Duration::ZERO);
	}
	if rest.is_empty() {
		return None;
	}
	let mut total = 0f64;
	while !rest.is_empty() {
		let number_len = rest
			.find(|c: char| !(c.is_ascii_digit() || c == '.'))
			.unwrap_or(rest.len());
		let (number, after) = rest.split_at(number_len);
		if number.is_empty() || number == "." {
			return None;
		}
		let value: f64 = number.parse().ok()?;
		let unit_len = after
			.find(|c: char| c.is_ascii_digit() || c == '.')
			.unwrap_or(after.len());
		let (unit, after) = after.split_at(unit_len);
		let nanos_per_unit = match unit {
			"ns" => 1.0,
			"us" | "µs" | "μs" => 1e3,
			"ms" => 1e6,
			"s" => 1e9,
			"m" => 60e9,
			"h" => 3600e9,
			_ => return None,
		};
		total += value * nanos_per_unit;
		rest = after;
	}
	if negative {
		return (total == 0.0).then_some(Duration::ZERO).or(None);
	}
	Some(Duration::from_nanos(total.round() as u64))
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	#[test]
	fn parses_peer_uris() {
		let uri = PeerUri::parse("TLS://[fe80::1%25eth0]:1234?key=ab&priority=2").unwrap();
		assert_eq!(uri.scheme, "tls");
		assert_eq!(uri.host, "[fe80::1%eth0]:1234");
		assert_eq!(uri.host_port().unwrap(), ("fe80::1%eth0".to_string(), 1234));
		assert_eq!(uri.query_value("priority"), Some("2"));
		assert_eq!(
			uri.without_query().to_string(),
			"tls://[fe80::1%25eth0]:1234"
		);

		let uri = PeerUri::parse("socks://user:pass@proxy:1080/example.com:443").unwrap();
		assert_eq!(uri.user, Some(("user".into(), Some("pass".into()))));
		assert_eq!(uri.host, "proxy:1080");
		assert_eq!(uri.path, "/example.com:443");

		let uri = PeerUri::parse("unix:///var/run/ygg.sock").unwrap();
		assert_eq!(uri.host, "");
		assert_eq!(uri.path, "/var/run/ygg.sock");

		assert!(PeerUri::parse("no-scheme").is_err());
	}

	#[test]
	fn splits_host_ports_like_go() {
		assert_eq!(split_host_port("1.2.3.4:5").unwrap(), ("1.2.3.4".into(), 5));
		assert_eq!(split_host_port("[::1]:5").unwrap(), ("::1".into(), 5));
		assert!(split_host_port("::1:5").is_err());
		assert!(split_host_port("host").is_err());
		assert_eq!(join_host_port("::1", 5), "[::1]:5");
	}

	#[test]
	fn parses_go_durations() {
		assert_eq!(parse_go_duration("5s"), Some(Duration::from_secs(5)));
		assert_eq!(parse_go_duration("1h30m"), Some(Duration::from_secs(5400)));
		assert_eq!(parse_go_duration("1.5s"), Some(Duration::from_millis(1500)));
		assert_eq!(parse_go_duration("300ms"), Some(Duration::from_millis(300)));
		assert_eq!(parse_go_duration("0"), Some(Duration::ZERO));
		assert_eq!(parse_go_duration("5"), None);
		assert_eq!(parse_go_duration("s"), None);
		assert_eq!(parse_go_duration(""), None);
	}

	proptest! {
		#[test]
		fn display_round_trips(
			scheme in "[a-z][a-z0-9+.-]{0,6}",
			host in "[a-zA-Z0-9.%: \\[\\]-]{0,20}",
			path in "(/[a-zA-Z0-9.%:@ -]{0,10}){0,3}",
			query in proptest::collection::vec(("[a-z]{1,5}", ".{0,8}"), 0..4),
		) {
			let uri = PeerUri { scheme, user: None, host, path, query };
			prop_assert_eq!(PeerUri::parse(&uri.to_string()), Ok(uri));
		}

		#[test]
		fn durations_round_trip(millis in 0u64..10_000_000) {
			let text = format!("{}h{}m{}.{:03}s", millis / 3_600_000, millis / 60_000 % 60, millis / 1000 % 60, millis % 1000);
			prop_assert_eq!(parse_go_duration(&text), Some(Duration::from_millis(millis)));
		}
	}
}
