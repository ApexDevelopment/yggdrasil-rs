//! The built-in admin requests.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use petrified::types::PublicKey;
use serde::Serialize;
use serde_json::{Map, Value};

use super::{AdminSocket, string_arg};
use crate::address::addr_for_key;
use crate::core::{Core, PeerInfo};
use crate::version;

fn to_value(value: impl Serialize) -> Result<Value, String> {
	serde_json::to_value(value).map_err(|error| error.to_string())
}

/// Requests answered by other nodes, which Go's core registers itself.
pub(super) fn add_core_handlers(admin: &Arc<AdminSocket>) {
	let core = admin.core.clone();
	let _ = admin.add_handler(
		"getNodeInfo",
		"Request nodeinfo from a remote node by its public key",
		&["key"],
		move |args| {
			let core = core.clone();
			async move { core.get_node_info(&string_arg(&args, "key")?).await }
		},
	);
	type Remote = fn(Core, String) -> crate::core::BoxFuture<'static, Result<Value, String>>;
	let remotes: [(&str, Remote); 3] = [
		("debug_remoteGetSelf", |core, key| {
			Box::pin(async move { core.remote_get_self(&key).await })
		}),
		("debug_remoteGetPeers", |core, key| {
			Box::pin(async move { core.remote_get_peers(&key).await })
		}),
		("debug_remoteGetTree", |core, key| {
			Box::pin(async move { core.remote_get_tree(&key).await })
		}),
	];
	for (name, remote) in remotes {
		let core = admin.core.clone();
		let _ = admin.add_handler(name, "Debug use only", &["key"], move |args| {
			let core = core.clone();
			async move { remote(core, string_arg(&args, "key")?).await }
		});
	}
}

#[derive(Serialize)]
struct SelfResponse {
	build_name: &'static str,
	build_version: &'static str,
	key: String,
	address: String,
	routing_entries: u64,
	subnet: String,
}

#[derive(Serialize, Clone, Debug, PartialEq)]
struct PeerEntry {
	#[serde(rename = "remote", skip_serializing_if = "String::is_empty")]
	uri: String,
	up: bool,
	inbound: bool,
	#[serde(skip_serializing_if = "String::is_empty")]
	address: String,
	key: String,
	port: u64,
	priority: u64,
	cost: u64,
	#[serde(skip_serializing_if = "is_zero")]
	bytes_recvd: u64,
	#[serde(skip_serializing_if = "is_zero")]
	bytes_sent: u64,
	#[serde(skip_serializing_if = "is_zero")]
	rate_recvd: u64,
	#[serde(skip_serializing_if = "is_zero")]
	rate_sent: u64,
	#[serde(skip_serializing_if = "is_zero_float")]
	uptime: f64,
	/// Nanoseconds, as Go encodes a `time.Duration`.
	#[serde(skip_serializing_if = "is_zero")]
	latency: u64,
	#[serde(skip_serializing_if = "is_zero")]
	last_error_time: u64,
	#[serde(skip_serializing_if = "String::is_empty")]
	last_error: String,
}

fn is_zero(n: &u64) -> bool {
	*n == 0
}

fn is_zero_float(n: &f64) -> bool {
	*n == 0.0
}

fn nanos(duration: Duration) -> u64 {
	duration.as_nanos().min(u64::MAX as u128) as u64
}

impl PeerEntry {
	fn new(peer: PeerInfo) -> Self {
		let (key, address) = match peer.key {
			Some(key) => (hex::encode(key.0), addr_for_key(&key).to_string()),
			None => (String::new(), String::new()),
		};
		let since_error = peer
			.last_error_time
			.and_then(|time| SystemTime::now().duration_since(time).ok())
			.unwrap_or_default();
		PeerEntry {
			uri: peer.uri,
			up: peer.up,
			inbound: peer.inbound,
			address,
			key,
			port: peer.port,
			priority: peer.priority.into(),
			cost: peer.cost,
			bytes_recvd: peer.rx_bytes,
			bytes_sent: peer.tx_bytes,
			rate_recvd: peer.rx_rate,
			rate_sent: peer.tx_rate,
			uptime: peer.uptime.as_secs_f64(),
			latency: nanos(peer.latency),
			last_error_time: if peer.last_error.is_some() {
				nanos(since_error)
			} else {
				0
			},
			last_error: peer.last_error.unwrap_or_default(),
		}
	}
}

fn sort_peers(peers: &mut [PeerEntry], by: &str) {
	let by_key = |a: &PeerEntry, b: &PeerEntry| a.key.cmp(&b.key);
	let by_priority = |a: &PeerEntry, b: &PeerEntry| a.priority.cmp(&b.priority);
	let by_cost = |a: &PeerEntry, b: &PeerEntry| a.cost.cmp(&b.cost);
	let by_uptime = |a: &PeerEntry, b: &PeerEntry| a.uptime.total_cmp(&b.uptime);
	match by.to_lowercase().as_str() {
		"uptime" => peers.sort_by(|a, b| {
			by_uptime(a, b)
				.then_with(|| by_key(a, b))
				.then_with(|| by_priority(a, b))
				.then_with(|| by_cost(a, b))
		}),
		"cost" => peers.sort_by(|a, b| {
			by_cost(a, b)
				.then_with(|| by_key(a, b))
				.then_with(|| by_priority(a, b))
				.then_with(|| by_uptime(a, b))
		}),
		_ => peers.sort_by(|a, b| {
			a.inbound
				.cmp(&b.inbound)
				.then_with(|| by_key(a, b))
				.then_with(|| by_priority(a, b))
				.then_with(|| by_cost(a, b))
				.then_with(|| by_uptime(a, b))
		}),
	}
}

#[derive(Serialize)]
struct TreeEntry {
	address: String,
	key: String,
	parent: String,
	sequence: u64,
}

#[derive(Serialize)]
struct PathEntry {
	address: String,
	key: String,
	path: Vec<u64>,
	sequence: u64,
}

#[derive(Serialize)]
struct SessionEntry {
	address: String,
	key: String,
	bytes_recvd: u64,
	bytes_sent: u64,
	uptime: f64,
}

fn wrap(name: &str, items: Value) -> Value {
	Value::Object(Map::from_iter([(name.to_string(), items)]))
}

pub(super) fn add_node_handlers(admin: &Arc<AdminSocket>) {
	let core = admin.core.clone();
	let _ = admin.add_handler("getSelf", "Show details about this node", &[], move |_| {
		let core = core.clone();
		async move {
			let this = core.get_self();
			to_value(SelfResponse {
				build_name: version::build_name(),
				build_version: version::build_version(),
				key: hex::encode(this.key.0),
				address: core.address().to_string(),
				routing_entries: this.routing_entries,
				subnet: core.subnet().to_string(),
			})
		}
	});

	let core = admin.core.clone();
	let _ = admin.add_handler(
		"getPeers",
		"Show directly connected peers",
		&["sort"],
		move |args| {
			let core = core.clone();
			async move {
				let by = string_arg(&args, "sort")?;
				let mut peers: Vec<PeerEntry> =
					core.get_peers().into_iter().map(PeerEntry::new).collect();
				sort_peers(&mut peers, &by);
				Ok(wrap("peers", to_value(peers)?))
			}
		},
	);

	let core = admin.core.clone();
	let _ = admin.add_handler("getTree", "Show known Tree entries", &[], move |_| {
		let core = core.clone();
		async move {
			let mut tree: Vec<TreeEntry> = core
				.get_tree()
				.into_iter()
				.map(|entry| TreeEntry {
					address: addr_for_key(&entry.key).to_string(),
					key: hex::encode(entry.key.0),
					parent: hex::encode(entry.parent.0),
					sequence: entry.sequence,
				})
				.collect();
			tree.sort_by(|a, b| a.key.cmp(&b.key));
			Ok(wrap("tree", to_value(tree)?))
		}
	});

	let core = admin.core.clone();
	let _ = admin.add_handler(
		"getPaths",
		"Show established paths through this node",
		&[],
		move |_| {
			let core = core.clone();
			async move {
				let mut paths: Vec<PathEntry> = core
					.get_paths()
					.into_iter()
					.map(|path| PathEntry {
						address: addr_for_key(&path.key).to_string(),
						key: hex::encode(path.key.0),
						path: path.path,
						sequence: path.sequence,
					})
					.collect();
				paths.sort_by(|a, b| a.key.cmp(&b.key));
				Ok(wrap("paths", to_value(paths)?))
			}
		},
	);

	let core = admin.core.clone();
	let _ = admin.add_handler(
		"getSessions",
		"Show established traffic sessions with remote nodes",
		&[],
		move |_| {
			let core = core.clone();
			async move {
				let mut sessions: Vec<SessionEntry> = core
					.get_sessions()
					.into_iter()
					.map(|session| SessionEntry {
						address: addr_for_key(&session.key).to_string(),
						key: hex::encode(session.key.0),
						bytes_recvd: session.rx_bytes,
						bytes_sent: session.tx_bytes,
						uptime: session.uptime.as_secs_f64(),
					})
					.collect();
				sessions.sort_by(|a, b| a.key.cmp(&b.key));
				Ok(wrap("sessions", to_value(sessions)?))
			}
		},
	);

	let core = admin.core.clone();
	let _ = admin.add_handler(
		"addPeer",
		"Add a peer to the peer list",
		&["uri", "interface"],
		move |args| {
			let core = core.clone();
			async move {
				core.add_peer(&string_arg(&args, "uri")?, &string_arg(&args, "interface")?)
					.map_err(|error| error.to_string())?;
				Ok(Value::Object(Map::new()))
			}
		},
	);

	let core = admin.core.clone();
	let _ = admin.add_handler(
		"removePeer",
		"Remove a peer from the peer list",
		&["uri", "interface"],
		move |args| {
			let core = core.clone();
			async move {
				core.remove_peer(&string_arg(&args, "uri")?, &string_arg(&args, "interface")?)
					.map_err(|error| error.to_string())?;
				Ok(Value::Object(Map::new()))
			}
		},
	);
}

#[derive(Serialize)]
struct LookupEntry {
	addr: String,
	key: String,
	path: Vec<u64>,
	time: i64,
}

/// Each looked-up key's path and when the lookup arrived.
type LookupRecords = Arc<Mutex<HashMap<PublicKey, (Vec<u64>, SystemTime)>>>;

/// Records the lookups this node handles, for the `lookups` request.
pub(super) fn add_lookups_handler(admin: &Arc<AdminSocket>) {
	let lookups: LookupRecords = Arc::default();
	let recorder = lookups.clone();
	admin.core.set_lookup_logger(move |info| {
		recorder
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.insert(info.key, (info.path.clone(), SystemTime::now()));
	});
	let _ = admin.add_handler(
		"lookups",
		"Dump a record of lookups received in the past hour",
		&[],
		move |_| {
			let lookups = lookups.clone();
			async move {
				let mut lookups = lookups
					.lock()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
				let mut infos = Vec::with_capacity(lookups.len());
				for (key, (path, time)) in lookups.iter() {
					infos.push(LookupEntry {
						addr: addr_for_key(key).to_string(),
						key: hex::encode(key.0),
						path: path.clone(),
						time: time
							.duration_since(UNIX_EPOCH)
							.map(|since| since.as_secs() as i64)
							.unwrap_or_default(),
					});
				}
				let day = Duration::from_secs(24 * 60 * 60);
				lookups.retain(|_, (_, time)| time.elapsed().map(|age| age <= day).unwrap_or(true));
				Ok(wrap("infos", to_value(infos)?))
			}
		},
	);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn entry(key: &str, inbound: bool, uptime: f64) -> PeerEntry {
		PeerEntry {
			uri: String::new(),
			up: true,
			inbound,
			address: String::new(),
			key: key.into(),
			port: 0,
			priority: 0,
			cost: 0,
			bytes_recvd: 0,
			bytes_sent: 0,
			rate_recvd: 0,
			rate_sent: 0,
			uptime,
			latency: 0,
			last_error_time: 0,
			last_error: String::new(),
		}
	}

	#[test]
	fn sorts_outbound_first_then_by_key() {
		let mut peers = vec![
			entry("b", true, 1.0),
			entry("c", false, 1.0),
			entry("a", false, 1.0),
		];
		sort_peers(&mut peers, "");
		let keys: Vec<_> = peers
			.iter()
			.map(|peer| (peer.key.as_str(), peer.inbound))
			.collect();
		assert_eq!(keys, [("a", false), ("c", false), ("b", true)]);
	}

	#[test]
	fn sorts_by_exact_uptime_and_large_costs() {
		let mut peers = vec![
			entry("b", false, 1.5),
			entry("a", false, 1.2),
			entry("c", false, 0.1),
		];
		sort_peers(&mut peers, "uptime");
		let keys: Vec<_> = peers.iter().map(|peer| peer.key.as_str()).collect();
		assert_eq!(keys, ["c", "a", "b"]);

		let mut peers = vec![entry("a", false, 0.0), entry("b", false, 0.0)];
		peers[0].cost = u64::MAX;
		sort_peers(&mut peers, "cost");
		assert_eq!(peers[0].key, "b");
	}
}
