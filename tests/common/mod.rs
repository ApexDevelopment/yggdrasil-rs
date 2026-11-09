//! Helpers for the interop tests: building and driving yggdrasil-go.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// Builds the Go harness and yggdrasil-go's binaries once per test binary,
/// returning the directory that holds them.
pub fn go_bin_dir() -> PathBuf {
	static DIR: OnceLock<PathBuf> = OnceLock::new();
	DIR.get_or_init(|| {
		let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
		let exe = std::env::current_exe().unwrap();
		let name = exe.file_stem().unwrap().to_string_lossy().into_owned();
		let out = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("interop-go-{name}"));
		let status = Command::new("sh")
			.arg(root.join("interop/build.sh"))
			.arg(&out)
			.status()
			.expect("failed to run interop/build.sh");
		assert!(
			status.success(),
			"building the Go harness failed; these tests need a Go toolchain (set GO=/path/to/go if it is not on PATH)"
		);
		out
	})
	.clone()
}

pub fn go_bin(name: &str) -> PathBuf {
	go_bin_dir().join(name)
}

pub fn rust_bin(name: &str) -> PathBuf {
	match name {
		"yggdrasil" => PathBuf::from(env!("CARGO_BIN_EXE_yggdrasil")),
		"yggdrasilctl" => PathBuf::from(env!("CARGO_BIN_EXE_yggdrasilctl")),
		other => panic!("unknown binary {other}"),
	}
}

/// The harness in `vectors` mode, answering one JSON request per line.
pub struct Vectors {
	child: Child,
	stdin: ChildStdin,
	stdout: BufReader<ChildStdout>,
}

impl Vectors {
	fn spawn() -> Self {
		let mut child = Command::new(go_bin("harness-bin"))
			.arg("vectors")
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.expect("failed to start the Go harness");
		let stdin = child.stdin.take().unwrap();
		let stdout = BufReader::new(child.stdout.take().unwrap());
		Vectors {
			child,
			stdin,
			stdout,
		}
	}

	pub fn call(&mut self, request: Value) -> Value {
		writeln!(self.stdin, "{request}").unwrap();
		self.stdin.flush().unwrap();
		let mut line = String::new();
		self.stdout.read_line(&mut line).unwrap();
		serde_json::from_str(&line)
			.unwrap_or_else(|_| panic!("bad harness reply {line:?} to {request}"))
	}
}

impl Drop for Vectors {
	fn drop(&mut self) {
		let _ = self.child.kill();
	}
}

/// Asks the shared vectors harness.
pub fn vectors(request: Value) -> Value {
	static VECTORS: OnceLock<Mutex<Vectors>> = OnceLock::new();
	VECTORS
		.get_or_init(|| Mutex::new(Vectors::spawn()))
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
		.call(request)
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
	TcpListener::bind("127.0.0.1:0")
		.unwrap()
		.local_addr()
		.unwrap()
		.port()
}

/// Polls `check` until it returns `Some`, or panics after `timeout`.
pub fn wait_for<T>(timeout: Duration, what: &str, mut check: impl FnMut() -> Option<T>) -> T {
	let deadline = Instant::now() + timeout;
	loop {
		if let Some(result) = check() {
			return result;
		}
		assert!(Instant::now() < deadline, "timed out waiting for {what}");
		thread::sleep(Duration::from_millis(100));
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Implementation {
	Go,
	Rust,
}

impl Implementation {
	pub fn bin(self, name: &str) -> PathBuf {
		match self {
			Implementation::Go => go_bin(name),
			Implementation::Rust => rust_bin(name),
		}
	}
}

/// A `yggdrasil` daemon of either implementation, with a TCP admin socket.
pub struct Daemon {
	pub implementation: Implementation,
	child: Child,
	pub admin: String,
	pub key: String,
	pub address: String,
	_dir: tempfile::TempDir,
}

impl Daemon {
	/// Starts a daemon. `config` is merged over a config with no TUN or multicast.
	pub fn start(implementation: Implementation, seed: u8, config: Value) -> Self {
		let dir = tempfile::tempdir().unwrap();
		let admin = format!("127.0.0.1:{}", free_port());
		let secret = yggdrasil::PrivateKey::from_seed(&[seed; 32]);
		let mut full = json!({
			"PrivateKey": hex::encode(secret.0),
			"IfName": "none",
			"MulticastInterfaces": [],
			"AdminListen": format!("tcp://{admin}"),
		});
		for (key, value) in config.as_object().unwrap() {
			full[key] = value.clone();
		}
		let path = dir.path().join("yggdrasil.conf");
		std::fs::write(&path, full.to_string()).unwrap();
		let log = std::fs::File::create(dir.path().join("log")).unwrap();
		let child = Command::new(implementation.bin("yggdrasil"))
			.arg("-useconffile")
			.arg(&path)
			.arg("-loglevel")
			.arg("debug")
			.stdout(log)
			.stderr(Stdio::null())
			.spawn()
			.expect("failed to start yggdrasil");
		let key = secret.public_key();
		let daemon = Daemon {
			implementation,
			child,
			admin,
			key: hex::encode(key.0),
			address: yggdrasil::address::addr_for_key(&key).to_string(),
			_dir: dir,
		};
		wait_for(Duration::from_secs(10), "the admin socket", || {
			TcpStream::connect(&daemon.admin).ok()
		});
		daemon
	}

	pub fn log(&self) -> String {
		std::fs::read_to_string(self._dir.path().join("log")).unwrap_or_default()
	}

	pub fn dir(&self) -> &Path {
		self._dir.path()
	}

	/// Sends an admin request and returns the whole response.
	pub fn request(&self, name: &str, arguments: Value) -> Value {
		admin_request(
			&self.admin,
			&json!({"request": name, "arguments": arguments}),
		)
	}

	/// The `response` of a successful admin request.
	pub fn call(&self, name: &str, arguments: Value) -> Value {
		let response = self.request(name, arguments);
		assert_eq!(response["status"], "success", "{name} failed: {response}");
		response["response"].clone()
	}

	/// Like [`Daemon::call`], retrying a few times. The first request to another
	/// node can be lost while the session is set up, in yggdrasil-go too.
	pub fn call_remote(&self, name: &str, arguments: Value) -> Value {
		for _ in 0..4 {
			let response = self.request(name, arguments.clone());
			if response["status"] == "success" {
				return response["response"].clone();
			}
		}
		panic!("{name} never succeeded");
	}

	/// The keys of peers whose links are up.
	pub fn peer_keys(&self) -> Vec<String> {
		self.call("getPeers", json!({}))["peers"]
			.as_array()
			.unwrap()
			.iter()
			.filter(|peer| peer["up"] == true)
			.map(|peer| peer["key"].as_str().unwrap().to_string())
			.collect()
	}

	pub fn wait_for_peer(&self, other: &Daemon) {
		wait_for(Duration::from_secs(20), "a peering", || {
			self.peer_keys().contains(&other.key).then_some(())
		});
	}

	/// Runs a `yggdrasilctl` of either implementation against this daemon.
	pub fn ctl(&self, implementation: Implementation, args: &[&str]) -> (bool, String) {
		let output = Command::new(implementation.bin("yggdrasilctl"))
			.arg(format!("-endpoint=tcp://{}", self.admin))
			.args(args)
			.output()
			.unwrap();
		(
			output.status.success(),
			String::from_utf8_lossy(&output.stdout).into_owned(),
		)
	}
}

impl Drop for Daemon {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// Sends one admin request and reads the response.
pub fn admin_request(admin: &str, request: &Value) -> Value {
	let mut stream = TcpStream::connect(admin).unwrap();
	stream
		.set_read_timeout(Some(Duration::from_secs(15)))
		.unwrap();
	// One write, so the server never closes with part of the request unread
	stream.write_all(format!("{request}\n").as_bytes()).unwrap();
	let mut text = String::new();
	stream.read_to_string(&mut text).unwrap();
	serde_json::from_str(&text).unwrap_or_else(|_| panic!("bad admin response {text:?}"))
}

/// The harness in `node` mode: a Go node with an IPv6 packet interface.
pub struct GoNode {
	child: Child,
	stdin: ChildStdin,
	lines: Receiver<String>,
	pub key: String,
	pub address: String,
	/// An address in the node's routed subnet.
	pub subnet_address: String,
	pub listen: String,
}

impl GoNode {
	pub fn spawn(seed: u8, listen: Option<&str>, password: &str) -> Self {
		let mut command = Command::new(go_bin("harness-bin"));
		command
			.args([
				"node",
				"-seed",
				&hex::encode([seed; 32]),
				"-password",
				password,
			])
			.stdin(Stdio::piped())
			.stdout(Stdio::piped());
		if let Some(listen) = listen {
			command.args(["-listen", listen]);
		}
		let mut child = command.spawn().expect("failed to start the Go harness");
		let stdin = child.stdin.take().unwrap();
		let stdout = BufReader::new(child.stdout.take().unwrap());
		let (sender, lines) = channel();
		thread::spawn(move || {
			for line in stdout.lines().map_while(Result::ok) {
				if sender.send(line).is_err() {
					return;
				}
			}
		});
		let ready = lines
			.recv_timeout(Duration::from_secs(10))
			.expect("Go node did not start");
		let fields: Vec<&str> = ready.split_whitespace().collect();
		assert_eq!(fields[0], "ready", "unexpected line {ready:?}");
		GoNode {
			key: fields[1].into(),
			address: fields[2].into(),
			subnet_address: fields[3].into(),
			listen: fields[4].into(),
			child,
			stdin,
			lines,
		}
	}

	fn command(&mut self, line: &str, reply: &str) -> String {
		writeln!(self.stdin, "{line}").unwrap();
		self.stdin.flush().unwrap();
		loop {
			let line = self
				.lines
				.recv_timeout(Duration::from_secs(10))
				.expect("no reply");
			if let Some(rest) = line.strip_prefix(reply) {
				return rest.trim().to_string();
			}
		}
	}

	pub fn peer(&mut self, uri: &str) {
		let error = self.command(&format!("peer {uri}"), "peered");
		assert!(error.is_empty(), "peering failed: {error}");
	}

	/// Sends an IPv6 packet carrying `payload` and no next header.
	pub fn send(&mut self, src: &str, dst: &str, payload: &[u8]) {
		let error = self.command(
			&format!("send {src} {dst} {}", hex::encode(payload)),
			"sent",
		);
		assert!(error.is_empty(), "send failed: {error}");
	}

	/// Waits for a packet, returning its source, destination and payload.
	pub fn recv(&mut self, timeout: Duration) -> Option<(String, String, Vec<u8>)> {
		let deadline = Instant::now() + timeout;
		loop {
			let line = self
				.lines
				.recv_timeout(deadline.saturating_duration_since(Instant::now()))
				.ok()?;
			let fields: Vec<&str> = line.split_whitespace().collect();
			if fields.first() == Some(&"recv") {
				return Some((
					fields[1].into(),
					fields[2].into(),
					hex::decode(fields.get(3).unwrap_or(&"")).unwrap(),
				));
			}
		}
	}
}

impl Drop for GoNode {
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

/// An IPv6 packet with no next header, carrying `payload`.
pub fn ipv6_packet(src: &str, dst: &str, payload: &[u8]) -> Vec<u8> {
	let src: std::net::Ipv6Addr = src.parse().unwrap();
	let dst: std::net::Ipv6Addr = dst.parse().unwrap();
	let mut packet = vec![0x60, 0, 0, 0];
	packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
	packet.extend_from_slice(&[59, 64]);
	packet.extend_from_slice(&src.octets());
	packet.extend_from_slice(&dst.octets());
	packet.extend_from_slice(payload);
	packet
}
