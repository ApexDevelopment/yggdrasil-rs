//! Real TUN adapters: each node runs in its own unprivileged network namespace,
//! peered over a UNIX socket, and the kernel pings across Yggdrasil.
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};

use common::Implementation::{self, Go, Rust};
use serde_json::{Value, json};
use yggdrasil::PrivateKey;
use yggdrasil::address::addr_for_key;

fn namespaces_available() -> bool {
	let unshare = Command::new("unshare")
		.args(["-rn", "true"])
		.stderr(Stdio::null())
		.status()
		.is_ok_and(|status| status.success());
	unshare && Path::new("/dev/net/tun").exists()
}

fn write_config(dir: &Path, name: &str, seed: u8, settings: Value) -> String {
	let mut config = json!({
		"PrivateKey": hex::encode(PrivateKey::from_seed(&[seed; 32]).0),
		"IfName": "auto",
		"MulticastInterfaces": [],
		"AdminListen": "none",
	});
	for (key, value) in settings.as_object().unwrap() {
		config[key] = value.clone();
	}
	let path = dir.join(name);
	std::fs::write(&path, config.to_string()).unwrap();
	path.to_str().unwrap().to_string()
}

/// Runs `script` in a new user and network namespace with `$0` set to the
/// `yggdrasil` binary and `$1` to its config.
fn in_namespace(implementation: Implementation, config: &str, script: &str) -> Command {
	let mut command = Command::new("unshare");
	command
		.args(["-rn", "sh", "-c", &format!("ip link set lo up && {script}")])
		.arg(implementation.bin("yggdrasil"))
		.arg(config);
	command
}

struct Namespaced(Child);

impl Drop for Namespaced {
	fn drop(&mut self) {
		let _ = self.0.kill();
		let _ = self.0.wait();
	}
}

/// Starts `server` listening on a UNIX socket, then pings it from a `client`
/// namespace with `ping_args`. Returns the ping output.
fn ping_across(
	server: Implementation,
	client: Implementation,
	server_mtu: u64,
	ping_args: &str,
) -> String {
	let dir = tempfile::tempdir().unwrap();
	let socket = format!("unix://{}", dir.path().join("peer.sock").display());
	let server_config = write_config(
		dir.path(),
		"server.conf",
		41,
		json!({"Listen": [socket], "IfMTU": server_mtu}),
	);
	let client_config = write_config(dir.path(), "client.conf", 42, json!({"Peers": [socket]}));
	let target = addr_for_key(&PrivateKey::from_seed(&[41; 32]).public_key()).to_string();
	let _server = Namespaced(
		in_namespace(server, &server_config, "exec \"$0\" -useconffile \"$1\"")
			.stdout(Stdio::null())
			.stderr(Stdio::null())
			.spawn()
			.unwrap(),
	);
	// Retry while the link comes up and the route is found
	let script = format!(
		"\"$0\" -useconffile \"$1\" >/dev/null 2>&1 & sleep 1; for i in $(seq 30); do ping -6 -c 1 -W 1 {ping_args} {target} && break; done; kill -9 $!"
	);
	let output = in_namespace(client, &client_config, &script)
		.output()
		.unwrap();
	String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn kernels_ping_across_implementations() {
	if !namespaces_available() {
		eprintln!("skipping: unprivileged network namespaces or /dev/net/tun are unavailable");
		return;
	}
	for (server, client) in [(Rust, Go), (Go, Rust), (Rust, Rust)] {
		let output = ping_across(server, client, 65535, "");
		assert!(
			output.contains(" 0% packet loss"),
			"{server:?} <- {client:?}:\n{output}"
		);
	}
}

#[test]
fn oversized_packets_get_packet_too_big_replies() {
	if !namespaces_available() {
		eprintln!("skipping: unprivileged network namespaces or /dev/net/tun are unavailable");
		return;
	}
	for (server, client) in [(Rust, Go), (Go, Rust)] {
		// The client's TUN takes the packet, but the server's MTU is smaller
		let output = ping_across(server, client, 1280, "-s 1400");
		assert!(
			output.contains("mtu=1280"),
			"{server:?} <- {client:?}:\n{output}"
		);
	}
}
