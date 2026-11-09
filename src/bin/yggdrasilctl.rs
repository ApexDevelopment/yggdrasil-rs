//! Sends a request to a node's admin socket and prints the response, like yggdrasil-go's yggdrasilctl.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::ExitCode;

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use yggdrasil::cli::flags::{Flags, ParseError};
use yggdrasil::cli::table::Table;
use yggdrasil::config::{get_defaults, read_admin_listen};
use yggdrasil::core::uri::PeerUri;
use yggdrasil::version;

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

#[derive(Deserialize)]
struct Response {
	#[serde(default)]
	status: String,
	#[serde(default)]
	error: String,
	response: Option<Box<RawValue>>,
}

/// Collects log lines, which are only shown if something goes wrong.
#[derive(Default)]
struct LogBuffer(Vec<String>);

impl LogBuffer {
	fn log(&mut self, line: impl Into<String>) {
		self.0.push(line.into());
	}

	fn fail(&self, error: impl std::fmt::Display) -> ExitCode {
		for line in &self.0 {
			println!("{line}");
		}
		println!("Fatal error: {error}");
		ExitCode::FAILURE
	}
}

fn flags(default_endpoint: &str) -> Flags {
	Flags::default()
		.string("endpoint", default_endpoint, "Admin socket endpoint")
		.bool(
			"json",
			false,
			"Output in JSON format (as opposed to pretty-print)",
		)
		.bool("borders", true, "Output borders on tables")
		.bool("version", false, "Prints the version of this build")
}

fn usage(flags: &Flags) {
	let program = std::env::args()
		.next()
		.unwrap_or_else(|| "yggdrasilctl".into());
	println!("Usage: {program} [options] command [key=value] [key=value] ...\n");
	println!("Options:");
	print!("{}", flags.defaults());
	println!();
	println!(
		"Please note that options must always specified BEFORE the command\non the command line or they will be ignored."
	);
	println!();
	println!("Commands:\n  - Use \"list\" for a list of available commands");
	println!();
	println!("Examples:");
	println!("  -  {program} list");
	println!("  -  {program} getPeers");
	println!("  -  {program} -endpoint=tcp://localhost:9001 getPeers");
	println!("  -  {program} -endpoint=unix:///var/run/ygg.sock getPeers");
}

/// The endpoint to use: from the command line, else the default config file, else the platform default.
fn endpoint(given: &str, logs: &mut LogBuffer) -> String {
	let defaults = get_defaults();
	if given != defaults.admin_listen {
		logs.log(format!("Using endpoint {given} from command line"));
		return given.to_string();
	}
	match std::fs::read(&defaults.config_file) {
		Ok(data) => match read_admin_listen(&data) {
			Ok(Some(listen)) => {
				logs.log(format!(
					"Found platform default config file {}",
					defaults.config_file
				));
				logs.log(format!("Using endpoint {listen} from AdminListen"));
				listen
			}
			_ => {
				logs.log("Configuration file doesn't contain appropriate AdminListen option");
				logs.log(format!(
					"Falling back to platform default {}",
					defaults.admin_listen
				));
				defaults.admin_listen
			}
		},
		Err(_) => {
			logs.log(format!(
				"Can't open config file from default location {}",
				defaults.config_file
			));
			logs.log(format!(
				"Falling back to platform default {}",
				defaults.admin_listen
			));
			defaults.admin_listen
		}
	}
}

fn connect(endpoint: &str, logs: &mut LogBuffer) -> Result<Box<dyn Stream>, String> {
	match PeerUri::parse(endpoint) {
		Ok(uri) => match uri.scheme.as_str() {
			#[cfg(unix)]
			"unix" => {
				let path = &endpoint["unix://".len()..];
				logs.log(format!("Connecting to UNIX socket {path}"));
				Ok(Box::new(
					std::os::unix::net::UnixStream::connect(path).map_err(|e| e.to_string())?,
				))
			}
			"tcp" => {
				logs.log(format!("Connecting to TCP socket {}", uri.host));
				Ok(Box::new(
					std::net::TcpStream::connect(&uri.host).map_err(|e| e.to_string())?,
				))
			}
			_ => {
				logs.log("Unknown protocol or malformed address - check your endpoint");
				Err("protocol not supported".into())
			}
		},
		Err(_) => {
			logs.log(format!("Connecting to TCP socket {endpoint}"));
			Ok(Box::new(
				std::net::TcpStream::connect(endpoint).map_err(|e| e.to_string())?,
			))
		}
	}
}

fn main() -> ExitCode {
	let flags = flags(&get_defaults().admin_listen);
	let parsed = match flags.parse(std::env::args().skip(1)) {
		Ok(parsed) => parsed,
		Err(ParseError::Help) => {
			usage(&flags);
			return ExitCode::SUCCESS;
		}
		Err(ParseError::Invalid(error)) => {
			eprintln!("{error}");
			usage(&flags);
			return ExitCode::from(2);
		}
	};
	if parsed.bool("version") {
		let program = std::env::args()
			.next()
			.unwrap_or_else(|| "yggdrasilctl".into());
		println!("Build name: {}", version::build_name());
		println!("Build version: {}", version::build_version());
		println!("To get the version number of the running Yggdrasil node, run {program} getSelf");
		return ExitCode::SUCCESS;
	}
	if parsed.args.is_empty() {
		usage(&flags);
		return ExitCode::SUCCESS;
	}

	let mut logs = LogBuffer::default();
	let endpoint = endpoint(&parsed.string("endpoint"), &mut logs);
	let mut conn = match connect(&endpoint, &mut logs) {
		Ok(conn) => conn,
		Err(error) => return logs.fail(error),
	};
	logs.log("Connected");

	let mut name = String::new();
	let mut arguments = Map::new();
	for (i, arg) in parsed.args.iter().enumerate() {
		if i == 0 {
			if arg.starts_with('-') {
				logs.log(format!(
					"Ignoring flag {arg} as it should be specified before other parameters"
				));
				continue;
			}
			logs.log(format!("Sending request: {arg}"));
			name = arg.clone();
			continue;
		}
		match arg.split_once('=') {
			Some((key, value)) => {
				arguments.insert(key.to_string(), value.into());
			}
			None => logs.log(format!("Ignoring invalid argument: {arg}")),
		}
	}
	arguments.sort_keys();
	let mut request = Map::new();
	request.insert("request".into(), name.clone().into());
	request.insert("arguments".into(), Value::Object(arguments));
	let mut line = yggdrasil::json::to_string(&request).expect("serializable");
	line.push('\n');
	if let Err(error) = conn.write_all(line.as_bytes()) {
		return logs.fail(error);
	}
	logs.log("Request sent");

	let response = match read_response(conn) {
		Ok(response) => response,
		Err(error) => return logs.fail(error),
	};
	if response.status == "error" {
		if response.error.is_empty() {
			println!("Admin socket returned an error but didn't specify any error text");
		} else {
			println!("Admin socket returned an error: {}", response.error);
		}
		return ExitCode::FAILURE;
	}
	let raw = response
		.response
		.map(|raw| raw.get().to_string())
		.unwrap_or_else(|| "null".into());
	let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
	if parsed.bool("json") {
		println!(
			"{}",
			yggdrasil::json::to_string_pretty(&value).unwrap_or_default()
		);
		return ExitCode::SUCCESS;
	}
	match print_response(&name.to_lowercase(), &value, &raw, parsed.bool("borders")) {
		Ok(()) => ExitCode::SUCCESS,
		Err(error) => logs.fail(error),
	}
}

/// Reads one JSON document, which may span several lines.
fn read_response(conn: Box<dyn Stream>) -> Result<Response, String> {
	let mut reader = BufReader::new(conn);
	let mut text = String::new();
	loop {
		let read = reader.read_line(&mut text).map_err(|e| e.to_string())?;
		match serde_json::from_str(&text) {
			Ok(response) => return Ok(response),
			Err(error) if read == 0 || !error.is_eof() => return Err(error.to_string()),
			Err(_) => {}
		}
	}
}

fn text(value: &Value) -> String {
	match value {
		Value::String(text) => text.clone(),
		Value::Null => String::new(),
		other => other.to_string(),
	}
}

fn unsigned(value: &Value) -> u64 {
	value.as_u64().unwrap_or_default()
}

/// Go's `DataUnit.String`.
fn data_unit(bytes: u64) -> String {
	const KB: f64 = 1024.0;
	let value = bytes as f64;
	match bytes {
		b if b >= 1 << 40 => format!("{:2.1}TB", value / KB / KB / KB / KB),
		b if b >= 1 << 30 => format!("{:2.1}GB", value / KB / KB / KB),
		b if b >= 1 << 20 => format!("{:2.1}MB", value / KB / KB),
		b if b >= 100 => format!("{:2.1}KB", value / KB),
		b => format!("{b}B"),
	}
}

fn seconds(total: u64) -> String {
	yggdrasil::cli::go_duration(std::time::Duration::from_secs(total))
}

fn print_response(name: &str, value: &Value, raw: &str, borders: bool) -> Result<(), String> {
	let mut table = Table::new(borders);
	let items = |key: &str| value[key].as_array().cloned().unwrap_or_default();
	match name {
		"list" => {
			table.header(&["Command", "Arguments", "Description"]);
			for entry in items("list") {
				let fields: Vec<String> = entry["fields"]
					.as_array()
					.map(|fields| {
						fields
							.iter()
							.map(|field| format!("{}=...", text(field)))
							.collect()
					})
					.unwrap_or_default();
				table.row(vec![
					text(&entry["command"]),
					fields.join(", "),
					text(&entry["description"]),
				]);
			}
		}
		"getself" => {
			for (label, key) in [
				("Build name:", "build_name"),
				("Build version:", "build_version"),
				("IPv6 address:", "address"),
				("IPv6 subnet:", "subnet"),
				("Routing table size:", "routing_entries"),
				("Public key:", "key"),
			] {
				table.row(vec![label.into(), text(&value[key])]);
			}
		}
		"getpeers" => {
			table.header(&[
				"URI",
				"State",
				"Dir",
				"IP Address",
				"Uptime",
				"RTT",
				"RX",
				"TX",
				"Down",
				"Up",
				"Pr",
				"Cost",
				"Last Error",
			]);
			for peer in items("peers") {
				table.row(peer_row(&peer));
			}
		}
		"gettree" => {
			table.header(&["Public Key", "IP Address", "Parent", "Sequence"]);
			for entry in items("tree") {
				table.row(vec![
					text(&entry["key"]),
					text(&entry["address"]),
					text(&entry["parent"]),
					unsigned(&entry["sequence"]).to_string(),
				]);
			}
		}
		"getpaths" => {
			table.header(&["Public Key", "IP Address", "Path", "Seq"]);
			for entry in items("paths") {
				let path: Vec<String> = entry["path"]
					.as_array()
					.map(|path| path.iter().map(|hop| unsigned(hop).to_string()).collect())
					.unwrap_or_default();
				table.row(vec![
					text(&entry["key"]),
					text(&entry["address"]),
					format!("[{}]", path.join(" ")),
					unsigned(&entry["sequence"]).to_string(),
				]);
			}
		}
		"getsessions" => {
			table.header(&["Public Key", "IP Address", "Uptime", "RX", "TX"]);
			for entry in items("sessions") {
				table.row(vec![
					text(&entry["key"]),
					text(&entry["address"]),
					seconds(entry["uptime"].as_f64().unwrap_or_default() as u64),
					data_unit(unsigned(&entry["bytes_recvd"])),
					data_unit(unsigned(&entry["bytes_sent"])),
				]);
			}
		}
		"getnodeinfo" => {
			// The nodeinfo itself, exactly as the node sent it
			let raw: std::collections::BTreeMap<String, Box<RawValue>> =
				serde_json::from_str(raw).map_err(|e| e.to_string())?;
			if let Some(nodeinfo) = raw.values().next() {
				println!("{}", nodeinfo.get());
			}
			return Ok(());
		}
		"getmulticastinterfaces" => {
			let yes = |value: &Value| {
				if value.as_bool().unwrap_or_default() {
					"Yes"
				} else {
					"-"
				}
				.to_string()
			};
			table.header(&["Name", "Listen Address", "Beacon", "Listen", "Password"]);
			for entry in items("multicast_interfaces") {
				table.row(vec![
					text(&entry["name"]),
					text(&entry["address"]),
					yes(&entry["beacon"]),
					yes(&entry["listen"]),
					yes(&entry["password"]),
				]);
			}
		}
		"gettun" => {
			let enabled = value["enabled"].as_bool().unwrap_or_default();
			table.row(vec!["TUN enabled:".into(), enabled.to_string()]);
			if enabled {
				table.row(vec!["Interface name:".into(), text(&value["name"])]);
				table.row(vec![
					"Interface MTU:".into(),
					unsigned(&value["mtu"]).to_string(),
				]);
			}
		}
		"addpeer" | "removepeer" => return Ok(()),
		_ => {
			println!("{raw}");
			return Ok(());
		}
	}
	print!("{}", table.render());
	Ok(())
}

fn peer_row(peer: &Value) -> Vec<String> {
	let up = peer["up"].as_bool().unwrap_or_default();
	let mut state = "Up".to_string();
	let mut last_error = "-".to_string();
	let mut rtt = "-".to_string();
	if !up {
		state = "Down".into();
		let error = text(&peer["last_error"]);
		if !error.is_empty() {
			let nanos = unsigned(&peer["last_error_time"]);
			let rounded = (nanos + 500_000_000) / 1_000_000_000;
			last_error = format!("{} ago: {error}", seconds(rounded));
		}
	} else {
		let micros = unsigned(&peer["latency"]) / 1000;
		let millis = micros as f64 / 1000.0;
		if millis > 0.0 {
			rtt = format!("{millis:.2}ms");
		}
	}
	let dir = if peer["inbound"].as_bool().unwrap_or_default() {
		"In"
	} else {
		"Out"
	};
	let uri = text(&peer["remote"]);
	let uri = PeerUri::parse(&uri)
		.map(|parsed| parsed.without_query().to_string())
		.unwrap_or(uri);
	let rate = |key: &str| {
		let rate = unsigned(&peer[key]);
		if rate > 0 {
			format!("{}/s", data_unit(rate))
		} else {
			"-".into()
		}
	};
	vec![
		uri,
		state,
		dir.into(),
		text(&peer["address"]),
		seconds(peer["uptime"].as_f64().unwrap_or_default() as u64),
		rtt,
		data_unit(unsigned(&peer["bytes_recvd"])),
		data_unit(unsigned(&peer["bytes_sent"])),
		rate("rate_recvd"),
		rate("rate_sent"),
		unsigned(&peer["priority"]).to_string(),
		unsigned(&peer["cost"]).to_string(),
		last_error,
	]
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn formats_like_go() {
		assert_eq!(data_unit(99), "99B");
		assert_eq!(data_unit(100), "0.1KB");
		assert_eq!(data_unit(5 << 20), "5.0MB");
		assert_eq!(seconds(0), "0s");
		assert_eq!(seconds(3600), "1h0m0s");
		assert_eq!(seconds(65), "1m5s");
	}
}
