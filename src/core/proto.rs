//! Node-to-node requests carried in sessions: nodeinfo and remote debug queries.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use petrified::types::PublicKey;
use serde_json::{Map, Value};
use tokio::sync::{mpsc, oneshot};

use super::CoreInner;
use super::node::TYPE_SESSION_PROTO;
use crate::address::addr_for_key;
use crate::version;

const PROTO_NODEINFO_REQUEST: u8 = 1;
const PROTO_NODEINFO_RESPONSE: u8 = 2;
const PROTO_DEBUG: u8 = 255;

const DEBUG_GET_SELF_REQUEST: u8 = 1;
const DEBUG_GET_SELF_RESPONSE: u8 = 2;
const DEBUG_GET_PEERS_REQUEST: u8 = 3;
const DEBUG_GET_PEERS_RESPONSE: u8 = 4;
const DEBUG_GET_TREE_REQUEST: u8 = 5;
const DEBUG_GET_TREE_RESPONSE: u8 = 6;

const MAX_NODEINFO_SIZE: usize = 16384;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// What a request asks for, which is also the response type it waits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Request {
	NodeInfo,
	DebugSelf,
	DebugPeers,
	DebugTree,
}

impl Request {
	fn packet(self) -> Vec<u8> {
		match self {
			Request::NodeInfo => vec![TYPE_SESSION_PROTO, PROTO_NODEINFO_REQUEST],
			Request::DebugSelf => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_SELF_REQUEST],
			Request::DebugPeers => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_PEERS_REQUEST],
			Request::DebugTree => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_TREE_REQUEST],
		}
	}
}

#[derive(Default)]
pub(crate) struct Proto {
	nodeinfo: Mutex<Vec<u8>>,
	/// A newer request to the same node replaces an older one, as in Go.
	pending: Mutex<HashMap<(Request, PublicKey), oneshot::Sender<Vec<u8>>>>,
}

/// Builds this node's nodeinfo JSON from the configured map.
pub fn build_nodeinfo(given: &Map<String, Value>, privacy: bool) -> Result<Vec<u8>, String> {
	// Go marshals maps with sorted keys
	let mut nodeinfo: BTreeMap<String, Value> = given.clone().into_iter().collect();
	if !privacy {
		nodeinfo.insert("buildname".into(), version::build_name().into());
		nodeinfo.insert("buildversion".into(), version::build_version().into());
		nodeinfo.insert("buildplatform".into(), version::build_platform().into());
		nodeinfo.insert("buildarch".into(), version::build_arch().into());
	}
	let json = crate::json::to_string(&nodeinfo)
		.map_err(|error| format!("NodeInfo marshalling failed: {error}"))?;
	if json.len() > MAX_NODEINFO_SIZE {
		return Err("NodeInfo exceeds max length of 16384 bytes".into());
	}
	Ok(json.into_bytes())
}

impl Proto {
	pub fn set_nodeinfo(&self, nodeinfo: Vec<u8>) {
		*self
			.nodeinfo
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner()) = nodeinfo;
	}

	pub fn nodeinfo(&self) -> Vec<u8> {
		self.nodeinfo
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.clone()
	}

	fn complete(&self, request: Request, key: PublicKey, response: &[u8]) {
		let waiter = self
			.pending
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.remove(&(request, key));
		if let Some(waiter) = waiter {
			let _ = waiter.send(response.to_vec());
		}
	}
}

/// Answers and completes requests until the node closes.
pub(crate) async fn run(
	core: Arc<CoreInner>,
	mut packets: mpsc::UnboundedReceiver<(PublicKey, Vec<u8>)>,
) {
	loop {
		let packet = tokio::select! {
			packet = packets.recv() => packet,
			_ = core.cancel.cancelled() => None,
		};
		let Some((from, packet)) = packet else {
			return;
		};
		handle(&core, from, &packet);
	}
}

fn handle(core: &CoreInner, from: PublicKey, packet: &[u8]) {
	let Some((&kind, body)) = packet.split_first() else {
		return;
	};
	match kind {
		PROTO_NODEINFO_REQUEST => {
			let mut response = vec![TYPE_SESSION_PROTO, PROTO_NODEINFO_RESPONSE];
			response.extend_from_slice(&core.proto.nodeinfo());
			let _ = core.node.write_to(&response, &from);
		}
		PROTO_NODEINFO_RESPONSE => core.proto.complete(Request::NodeInfo, from, body),
		PROTO_DEBUG => handle_debug(core, from, body),
		_ => {}
	}
}

fn handle_debug(core: &CoreInner, from: PublicKey, packet: &[u8]) {
	let Some((&kind, body)) = packet.split_first() else {
		return;
	};
	let reply = |kind: u8, data: &[u8]| {
		let mut response = vec![TYPE_SESSION_PROTO, PROTO_DEBUG, kind];
		response.extend_from_slice(data);
		let _ = core.node.write_to(&response, &from);
	};
	match kind {
		DEBUG_GET_SELF_REQUEST => {
			let this = core.get_self();
			let mut response = Map::new();
			response.insert("key".into(), hex::encode(this.key.0).into());
			response.insert(
				"routing_entries".into(),
				this.routing_entries.to_string().into(),
			);
			if let Ok(json) = crate::json::to_string(&response) {
				reply(DEBUG_GET_SELF_RESPONSE, json.as_bytes());
			}
		}
		DEBUG_GET_PEERS_REQUEST => {
			let keys: Vec<PublicKey> = core
				.get_peers()
				.into_iter()
				.filter_map(|peer| peer.key)
				.collect();
			reply(DEBUG_GET_PEERS_RESPONSE, &pack_keys(&keys, core.mtu()));
		}
		DEBUG_GET_TREE_REQUEST => {
			let keys: Vec<PublicKey> = core.get_tree().into_iter().map(|entry| entry.key).collect();
			reply(DEBUG_GET_TREE_RESPONSE, &pack_keys(&keys, core.mtu()));
		}
		DEBUG_GET_SELF_RESPONSE => core.proto.complete(Request::DebugSelf, from, body),
		DEBUG_GET_PEERS_RESPONSE => core.proto.complete(Request::DebugPeers, from, body),
		DEBUG_GET_TREE_RESPONSE => core.proto.complete(Request::DebugTree, from, body),
		_ => {}
	}
}

/// Concatenates keys, stopping before the response would exceed the MTU.
fn pack_keys(keys: &[PublicKey], mtu: u64) -> Vec<u8> {
	// One byte each for the debug type and response type
	const RESPONSE_OVERHEAD: u64 = 2;
	let mut packed = Vec::new();
	for key in keys {
		if (packed.len() + key.0.len()) as u64 + RESPONSE_OVERHEAD > mtu {
			break;
		}
		packed.extend_from_slice(&key.0);
	}
	packed
}

fn unpack_keys(data: &[u8]) -> Value {
	let keys: Vec<Value> = data
		.chunks_exact(32)
		.map(|key| Value::String(hex::encode(key)))
		.collect();
	let mut result = Map::new();
	// Go omits the field entirely when there are no keys
	if !keys.is_empty() {
		result.insert("keys".into(), Value::Array(keys));
	}
	Value::Object(result)
}

fn parse_key(key: &str) -> Result<PublicKey, String> {
	let bytes = hex::decode(key).map_err(|error| error.to_string())?;
	let key: [u8; 32] = bytes
		.try_into()
		.map_err(|_| "invalid public key length".to_string())?;
	Ok(PublicKey(key))
}

impl CoreInner {
	async fn request(&self, request: Request, key: PublicKey) -> Option<Vec<u8>> {
		let (sender, receiver) = oneshot::channel();
		self.proto
			.pending
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.insert((request, key), sender);
		let _ = self.node.write_to(&request.packet(), &key);
		tokio::time::timeout(REQUEST_TIMEOUT, receiver)
			.await
			.ok()
			.and_then(Result::ok)
	}

	/// The admin `getNodeInfo` request: this node's nodeinfo, or a remote node's.
	pub async fn get_node_info(&self, key: &str) -> Result<Value, String> {
		let own = hex::encode(self.public.0);
		if key.is_empty() || key == own {
			let nodeinfo = serde_json::from_slice(&self.proto.nodeinfo())
				.map_err(|error| error.to_string())?;
			return Ok(Value::Object(Map::from_iter([(own, nodeinfo)])));
		}
		let remote = hex::decode(key)
			.map_err(|error| format!("failed to decode public key: {error}"))
			.and_then(|_| parse_key(key))?;
		let response = self
			.request(Request::NodeInfo, remote)
			.await
			.ok_or("timed out waiting for response")?;
		let nodeinfo: Value =
			serde_json::from_slice(&response).map_err(|error| error.to_string())?;
		Ok(Value::Object(Map::from_iter([(
			hex::encode(remote.0),
			nodeinfo,
		)])))
	}

	/// The admin `debug_remoteGet*` requests.
	async fn remote_debug(&self, request: Request, key: &str) -> Result<Value, String> {
		let remote = parse_key(key)?;
		let response = self.request(request, remote).await.ok_or("timeout")?;
		let value = match request {
			Request::DebugSelf => {
				serde_json::from_slice(&response).map_err(|error| error.to_string())?
			}
			_ => unpack_keys(&response),
		};
		let address = addr_for_key(&remote).to_string();
		Ok(Value::Object(Map::from_iter([(address, value)])))
	}

	pub async fn remote_get_self(&self, key: &str) -> Result<Value, String> {
		self.remote_debug(Request::DebugSelf, key).await
	}

	pub async fn remote_get_peers(&self, key: &str) -> Result<Value, String> {
		self.remote_debug(Request::DebugPeers, key).await
	}

	pub async fn remote_get_tree(&self, key: &str) -> Result<Value, String> {
		self.remote_debug(Request::DebugTree, key).await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn nodeinfo_includes_build_details_unless_private() {
		let mut given = Map::new();
		given.insert("name".into(), "alice".into());
		let public: Value =
			serde_json::from_slice(&build_nodeinfo(&given, false).unwrap()).unwrap();
		assert_eq!(public["name"], "alice");
		assert_eq!(public["buildname"], version::build_name());
		let private = build_nodeinfo(&given, true).unwrap();
		assert_eq!(private, br#"{"name":"alice"}"#);
	}

	#[test]
	fn rejects_oversized_nodeinfo() {
		let mut given = Map::new();
		given.insert("big".into(), "x".repeat(MAX_NODEINFO_SIZE).into());
		assert!(build_nodeinfo(&given, true).is_err());
	}

	#[test]
	fn packs_keys_within_mtu() {
		let keys = vec![PublicKey([1; 32]), PublicKey([2; 32]), PublicKey([3; 32])];
		assert_eq!(pack_keys(&keys, 1000).len(), 96);
		assert_eq!(pack_keys(&keys, 66).len(), 64);
		assert_eq!(
			unpack_keys(&pack_keys(&keys, 66))["keys"]
				.as_array()
				.unwrap()
				.len(),
			2
		);
		assert_eq!(unpack_keys(&[]), serde_json::json!({}));
	}
}
