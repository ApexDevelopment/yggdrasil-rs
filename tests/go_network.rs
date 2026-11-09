//! Live interop: yggdrasil-go and yggdrasil-rs nodes in the same networks.

mod common;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use common::{Daemon, GoNode, Implementation, free_port, go_bin, ipv6_packet, rust_bin, wait_for};
use serde_json::{Value, json};
use yggdrasil::PrivateKey;
use yggdrasil::core::{Core, Options};
use yggdrasil::ipv6rwc::ReadWriteCloser;

use Implementation::{Go, Rust};

/// Starts a listening daemon and a dialing daemon, and checks they peer and can query each other.
fn assert_daemons_peer(scheme: &str, listener: Implementation, dialer: Implementation) {
	let dir = tempfile::tempdir().unwrap();
	let listen = match scheme {
		"unix" => format!("unix://{}", dir.path().join("peer.sock").display()),
		_ => format!("{scheme}://127.0.0.1:{}", free_port()),
	};
	let a = Daemon::start(
		listener,
		1,
		json!({"Listen": [listen], "NodeInfo": {"name": "listener"}}),
	);
	let b = Daemon::start(
		dialer,
		2,
		json!({"Peers": [listen], "NodeInfo": {"name": "dialer"}}),
	);
	a.wait_for_peer(&b);
	b.wait_for_peer(&a);

	let nodeinfo = b.call_remote("getNodeInfo", json!({"key": a.key}));
	assert_eq!(nodeinfo[&a.key]["name"], "listener", "{scheme}: {nodeinfo}");
	let nodeinfo = a.call_remote("getNodeInfo", json!({"key": b.key}));
	assert_eq!(nodeinfo[&b.key]["name"], "dialer", "{scheme}: {nodeinfo}");
	let remote = b.call_remote("debug_remoteGetSelf", json!({"key": a.key}));
	assert_eq!(
		remote[&a.address]["key"],
		a.key.as_str(),
		"{scheme}: {remote}"
	);
	let remote = a.call_remote("debug_remoteGetPeers", json!({"key": b.key}));
	assert_eq!(
		remote[&b.address]["keys"],
		json!([a.key]),
		"{scheme}: {remote}"
	);
}

#[test]
fn daemons_peer_over_tcp() {
	assert_daemons_peer("tcp", Go, Rust);
	assert_daemons_peer("tcp", Rust, Go);
}

#[test]
fn daemons_peer_over_tls() {
	assert_daemons_peer("tls", Go, Rust);
	assert_daemons_peer("tls", Rust, Go);
}

#[test]
fn daemons_peer_over_quic() {
	assert_daemons_peer("quic", Go, Rust);
	assert_daemons_peer("quic", Rust, Go);
}

#[test]
fn daemons_peer_over_websockets() {
	assert_daemons_peer("ws", Go, Rust);
	assert_daemons_peer("ws", Rust, Go);
}

#[cfg(unix)]
#[test]
fn daemons_peer_over_unix_sockets() {
	assert_daemons_peer("unix", Go, Rust);
	assert_daemons_peer("unix", Rust, Go);
}

/// A SOCKS5 proxy that supports only unauthenticated CONNECT to IPv4 addresses.
fn socks_proxy() -> String {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let addr = listener.local_addr().unwrap().to_string();
	thread::spawn(move || {
		for client in listener.incoming() {
			let Ok(mut client) = client else { return };
			thread::spawn(move || {
				let mut greeting = [0u8; 2];
				client.read_exact(&mut greeting).unwrap();
				let mut methods = vec![0u8; greeting[1] as usize];
				client.read_exact(&mut methods).unwrap();
				client.write_all(&[5, 0]).unwrap();
				let mut request = [0u8; 10];
				client.read_exact(&mut request).unwrap();
				let ip = std::net::Ipv4Addr::new(request[4], request[5], request[6], request[7]);
				let port = u16::from_be_bytes([request[8], request[9]]);
				let target = TcpStream::connect((ip, port)).unwrap();
				client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
				let (mut client_reader, mut target_writer) =
					(client.try_clone().unwrap(), target.try_clone().unwrap());
				thread::spawn(move || std::io::copy(&mut client_reader, &mut target_writer));
				let (mut target_reader, mut client_writer) = (target, client);
				let _ = std::io::copy(&mut target_reader, &mut client_writer);
			});
		}
	});
	addr
}

#[test]
fn rust_reaches_go_through_socks() {
	let proxy = socks_proxy();
	for (scheme, target_scheme) in [("socks", "tcp"), ("sockstls", "tls")] {
		let target = format!("127.0.0.1:{}", free_port());
		let go = Daemon::start(
			Go,
			3,
			json!({"Listen": [format!("{target_scheme}://{target}")]}),
		);
		let rust = Daemon::start(
			Rust,
			4,
			json!({"Peers": [format!("{scheme}://{proxy}/{target}")]}),
		);
		go.wait_for_peer(&rust);
		rust.wait_for_peer(&go);
	}
}

#[test]
fn link_passwords_must_match() {
	let port = free_port();
	let go = Daemon::start(
		Go,
		5,
		json!({"Listen": [format!("tcp://127.0.0.1:{port}?password=secret")]}),
	);
	let right = Daemon::start(
		Rust,
		6,
		json!({"Peers": [format!("tcp://127.0.0.1:{port}?password=secret")]}),
	);
	let wrong = Daemon::start(
		Rust,
		7,
		json!({"Peers": [format!("tcp://127.0.0.1:{port}?password=wrong")]}),
	);
	right.wait_for_peer(&go);
	let error = wait_for(Duration::from_secs(10), "a handshake failure", || {
		let peers = wrong.call("getPeers", json!({}));
		peers["peers"][0]["last_error"].as_str().map(str::to_string)
	});
	assert_eq!(error, "password does not match remote side");
	assert!(!go.peer_keys().contains(&wrong.key));
}

#[test]
fn allowed_public_keys_are_enforced_by_both() {
	for (listener, dialer) in [(Go, Rust), (Rust, Go)] {
		let port = free_port();
		let allowed = PrivateKey::from_seed(&[9; 32]).public_key();
		let a = Daemon::start(
			listener,
			8,
			json!({"Listen": [format!("tcp://127.0.0.1:{port}")], "AllowedPublicKeys": [hex::encode(allowed.0)]}),
		);
		let permitted = Daemon::start(
			dialer,
			9,
			json!({"Peers": [format!("tcp://127.0.0.1:{port}")]}),
		);
		let refused = Daemon::start(
			dialer,
			10,
			json!({"Peers": [format!("tcp://127.0.0.1:{port}")]}),
		);
		a.wait_for_peer(&permitted);
		thread::sleep(Duration::from_secs(2));
		assert!(!a.peer_keys().contains(&refused.key));
	}
}

fn start_pair() -> (Daemon, Daemon) {
	let port = free_port();
	let go = Daemon::start(
		Go,
		11,
		json!({"Listen": [format!("tls://127.0.0.1:{port}")]}),
	);
	let rust = Daemon::start(
		Rust,
		12,
		json!({"Peers": [format!("tls://127.0.0.1:{port}")]}),
	);
	go.wait_for_peer(&rust);
	rust.wait_for_peer(&go);
	(go, rust)
}

/// The shape of a JSON value: its keys and types, without the values.
fn shape(value: &Value) -> Value {
	match value {
		Value::Object(map) => Value::Object(
			map.iter()
				.map(|(key, value)| (key.clone(), shape(value)))
				.collect(),
		),
		Value::Array(items) => Value::Array(items.iter().take(1).map(shape).collect()),
		Value::Bool(_) => json!("bool"),
		Value::Number(_) => json!("number"),
		Value::String(_) => json!("string"),
		Value::Null => json!("null"),
	}
}

#[test]
fn admin_sockets_answer_alike() {
	let (go, rust) = start_pair();
	assert_eq!(go.call("list", json!({})), rust.call("list", json!({})));
	for request in [
		"getSelf",
		"getPeers",
		"getTree",
		"getPaths",
		"getSessions",
		"getTun",
		"getMulticastInterfaces",
	] {
		let go_response = go.request(request, json!({}));
		let rust_response = rust.request(request, json!({}));
		assert_eq!(shape(&go_response), shape(&rust_response), "{request}");
	}
	for (request, arguments) in [
		("bogus", json!({})),
		("getNodeInfo", json!({"key": "zz"})),
		("debug_remoteGetSelf", json!({"key": "abcd"})),
		("removePeer", json!({"uri": "tcp://10.0.0.1:1"})),
		("addPeer", json!({"uri": "bogus://10.0.0.1:1"})),
	] {
		let go_response = go.request(request, arguments.clone());
		let rust_response = rust.request(request, arguments);
		assert_eq!(go_response["status"], "error");
		assert_eq!(go_response, rust_response, "{request}");
	}
	// Both must settle on the same spanning tree
	wait_for(Duration::from_secs(20), "the trees to agree", || {
		let tree = go.call("getTree", json!({}));
		(tree["tree"].as_array().unwrap().len() == 2 && tree == rust.call("getTree", json!({})))
			.then_some(())
	});
}

#[test]
fn ctls_are_interchangeable() {
	let (go, rust) = start_pair();
	for daemon in [&go, &rust] {
		for args in [
			&["list"][..],
			&["getSelf"],
			&["-borders=false", "getSelf"],
			&["getTree"],
			&["getTun"],
			&["getMulticastInterfaces"],
			&["-json", "getSelf"],
			&["-json", "getTree"],
			&["getNodeInfo"],
			&["bogus"],
		] {
			let from_go = daemon.ctl(Go, args);
			let from_rust = daemon.ctl(Rust, args);
			assert_eq!(
				from_go, from_rust,
				"{:?} against {:?}",
				args, daemon.implementation
			);
		}
		let (ok, peers) = daemon.ctl(Rust, &["getPeers"]);
		assert!(ok && peers.contains("Up"), "{peers}");
	}
	go.call_remote("getNodeInfo", json!({"key": rust.key}));
	let other_key = format!("key={}", rust.key);
	assert_eq!(
		go.ctl(Go, &["getNodeInfo", &other_key]),
		go.ctl(Rust, &["getNodeInfo", &other_key])
	);
}

/// Runs both `yggdrasil` binaries with the same config and arguments, and compares their output.
fn assert_cli_matches(config: &str, args: &[&str]) {
	let dir = tempfile::tempdir().unwrap();
	let path = dir.path().join("yggdrasil.conf");
	std::fs::write(&path, config).unwrap();
	let run = |bin: std::path::PathBuf| {
		let output = Command::new(bin)
			.arg("-useconffile")
			.arg(&path)
			.args(args)
			.output()
			.unwrap();
		String::from_utf8_lossy(&output.stdout).into_owned()
	};
	assert_eq!(
		run(go_bin("yggdrasil")),
		run(rust_bin("yggdrasil")),
		"{args:?} with {config}"
	);
	let stdin = |bin: std::path::PathBuf| {
		let mut child = Command::new(bin)
			.arg("-useconf")
			.args(args)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			.spawn()
			.unwrap();
		child
			.stdin
			.take()
			.unwrap()
			.write_all(config.as_bytes())
			.unwrap();
		String::from_utf8_lossy(&child.wait_with_output().unwrap().stdout).into_owned()
	};
	assert_eq!(
		stdin(go_bin("yggdrasil")),
		stdin(rust_bin("yggdrasil")),
		"-useconf {args:?}"
	);
}

#[test]
fn command_lines_match() {
	let key = hex::encode(PrivateKey::from_seed(&[13; 32]).0);
	let configs = [
		format!("{{\n  PrivateKey: {key}\n}}"),
		format!(
			"PrivateKey: {key}\nPeers: [\n  tls://a.b:1\n  \"#odd\"\n]\nNodeInfo: {{\n  name: x<y\n  n: 1.50\n  big: 1e21\n  list: [1, true, null]\n}}\nMulticastInterfaces: [{{Regex: \"eth0\"}}]\nIfMTU: 1500\nLogLookups: true"
		),
		format!(
			r#"{{"privatekey": "{key}", "InterfacePeers": {{"eth1": ["quic://[fe80::1%25eth1]:1"]}}, "AllowedPublicKeys": ["{}"], "GroupPassword": "12", "AdminListen": "none"}}"#,
			"ab".repeat(32)
		),
	];
	for config in &configs {
		for args in [
			&["-normaliseconf"][..],
			&["-normaliseconf", "-json"],
			&["-address"],
			&["-subnet"],
			&["-publickey"],
			&["-exportkey"],
		] {
			assert_cli_matches(config, args);
		}
	}
}

#[test]
fn key_files_are_read_alike() {
	let key = hex::encode(PrivateKey::from_seed(&[14; 32]).0);
	let dir = tempfile::tempdir().unwrap();
	let config = dir.path().join("config");
	std::fs::write(&config, format!("{{\"PrivateKey\": \"{key}\"}}")).unwrap();
	let pem = Command::new(go_bin("yggdrasil"))
		.args(["-useconffile", config.to_str().unwrap(), "-exportkey"])
		.output()
		.unwrap()
		.stdout;
	let pem_path = dir.path().join("key.pem");
	std::fs::write(&pem_path, pem).unwrap();
	let config = format!("{{\"PrivateKeyPath\": {:?}}}", pem_path.to_str().unwrap());
	assert_cli_matches(&config, &["-normaliseconf", "-json"]);
	assert_cli_matches(&config, &["-publickey"]);
}

#[test]
fn generated_configs_match() {
	let generate = |bin: std::path::PathBuf| {
		let output = Command::new(bin)
			.args(["-genconf", "-json"])
			.output()
			.unwrap();
		let mut config: Value = serde_json::from_slice(&output.stdout).unwrap();
		config["PrivateKey"] = json!("");
		config
	};
	assert_eq!(
		generate(go_bin("yggdrasil")),
		generate(rust_bin("yggdrasil"))
	);
	let hjson = |bin: std::path::PathBuf| {
		let output = Command::new(bin).arg("-genconf").output().unwrap();
		let text = String::from_utf8_lossy(&output.stdout).into_owned();
		text.lines()
			.map(|line| {
				if line.trim_start().starts_with("PrivateKey:") {
					"PrivateKey: <key>"
				} else {
					line
				}
			})
			.collect::<Vec<_>>()
			.join("\n")
	};
	assert_eq!(hjson(go_bin("yggdrasil")), hjson(rust_bin("yggdrasil")));
}

/// An in-process Rust node with an IPv6 packet interface.
struct RustNode {
	core: Core,
	rwc: ReadWriteCloser,
	received: Receiver<Vec<u8>>,
	address: String,
	subnet_address: String,
}

impl RustNode {
	fn start(runtime: &tokio::runtime::Runtime, seed: u8, password: &str) -> Self {
		let core = runtime
			.block_on(Core::new(
				PrivateKey::from_seed(&[seed; 32]),
				Options {
					group_password: password.into(),
					..Options::default()
				},
			))
			.unwrap();
		let rwc = ReadWriteCloser::new(core.clone());
		rwc.set_mtu(rwc.max_mtu());
		let (sender, received) = channel();
		let reader = rwc.clone();
		runtime.spawn(async move {
			let mut buf = vec![0u8; 65535];
			while let Ok(n) = reader.read(&mut buf).await {
				if sender.send(buf[..n].to_vec()).is_err() {
					return;
				}
			}
		});
		let mut subnet = core.subnet().to_ipv6().octets();
		subnet[15] = 1;
		RustNode {
			address: core.address().to_string(),
			subnet_address: std::net::Ipv6Addr::from(subnet).to_string(),
			core,
			rwc,
			received,
		}
	}

	fn listen(&self, runtime: &tokio::runtime::Runtime) -> String {
		let listener = runtime
			.block_on(self.core.listen("tcp://127.0.0.1:0", ""))
			.unwrap();
		format!("tcp://{}", listener.local_addr())
	}

	fn recv(&self, timeout: Duration) -> Option<(String, String, Vec<u8>)> {
		let packet = self.received.recv_timeout(timeout).ok()?;
		let address = |bytes: &[u8]| {
			std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string()
		};
		Some((
			address(&packet[8..24]),
			address(&packet[24..40]),
			packet[40..].to_vec(),
		))
	}
}

enum Node {
	Go(GoNode),
	Rust(RustNode),
}

impl Node {
	fn addresses(&self) -> (String, String) {
		match self {
			Node::Go(node) => (node.address.clone(), node.subnet_address.clone()),
			Node::Rust(node) => (node.address.clone(), node.subnet_address.clone()),
		}
	}

	fn send(&mut self, src: &str, dst: &str, payload: &[u8]) {
		match self {
			Node::Go(node) => node.send(src, dst, payload),
			Node::Rust(node) => {
				node.rwc.write(&ipv6_packet(src, dst, payload)).unwrap();
			}
		}
	}

	fn recv(&mut self, timeout: Duration) -> Option<(String, String, Vec<u8>)> {
		match self {
			Node::Go(node) => node.recv(timeout),
			Node::Rust(node) => node.recv(timeout),
		}
	}
}

/// Sends from `from` to `to` until a packet arrives, as the route may take a moment to appear.
fn assert_delivers(nodes: &mut [Node], from: usize, to: usize, to_subnet: bool) {
	let (src, _) = nodes[from].addresses();
	let (address, subnet_address) = nodes[to].addresses();
	let dst = if to_subnet { subnet_address } else { address };
	let payload = format!("{from}->{to}").into_bytes();
	let deadline = Instant::now() + Duration::from_secs(30);
	loop {
		nodes[from].send(&src, &dst, &payload);
		if let Some((got_src, got_dst, got)) = nodes[to].recv(Duration::from_millis(500)) {
			assert_eq!(
				(got_src.as_str(), got_dst.as_str(), &got[..]),
				(src.as_str(), dst.as_str(), &payload[..])
			);
			// Drain duplicates from retries
			while nodes[to].recv(Duration::from_millis(50)).is_some() {}
			return;
		}
		assert!(
			Instant::now() < deadline,
			"no delivery from node {from} to node {to} ({dst})"
		);
	}
}

#[test]
fn ipv6_traffic_crosses_implementations() {
	let runtime = tokio::runtime::Runtime::new().unwrap();
	// A chain alternating between implementations: Go - Rust - Go - Rust
	let go_first = GoNode::spawn(21, Some("tcp://127.0.0.1:0"), "");
	let rust_first = RustNode::start(&runtime, 22, "");
	let rust_first_listen = rust_first.listen(&runtime);
	rust_first
		.core
		.add_peer(&format!("tcp://{}", go_first.listen), "")
		.unwrap();
	let mut go_second = GoNode::spawn(23, Some("tcp://127.0.0.1:0"), "");
	go_second.peer(&rust_first_listen);
	let rust_second = RustNode::start(&runtime, 24, "");
	rust_second
		.core
		.add_peer(&format!("tcp://{}", go_second.listen), "")
		.unwrap();

	let mut nodes = [
		Node::Go(go_first),
		Node::Rust(rust_first),
		Node::Go(go_second),
		Node::Rust(rust_second),
	];
	for from in 0..nodes.len() {
		for to in 0..nodes.len() {
			if from != to {
				assert_delivers(&mut nodes, from, to, from % 2 == 0);
			}
		}
	}
}

#[test]
fn group_passwords_separate_networks() {
	let runtime = tokio::runtime::Runtime::new().unwrap();
	let go = GoNode::spawn(31, Some("tcp://127.0.0.1:0"), "group");
	let member = RustNode::start(&runtime, 32, "group");
	member
		.core
		.add_peer(&format!("tcp://{}", go.listen), "")
		.unwrap();
	let outsider = RustNode::start(&runtime, 33, "other");
	outsider
		.core
		.add_peer(&format!("tcp://{}", go.listen), "")
		.unwrap();
	let mut nodes = [Node::Go(go), Node::Rust(member), Node::Rust(outsider)];
	assert_delivers(&mut nodes, 0, 1, false);
	assert_delivers(&mut nodes, 1, 0, false);

	let (src, _) = nodes[2].addresses();
	let (dst, _) = nodes[0].addresses();
	for _ in 0..20 {
		nodes[2].send(&src, &dst, b"let me in");
		assert!(nodes[0].recv(Duration::from_millis(200)).is_none());
	}
}
