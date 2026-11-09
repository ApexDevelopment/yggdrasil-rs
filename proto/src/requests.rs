//! Node-to-node requests carried in sessions: nodeinfo and remote debug
//! queries, as in yggdrasil-go's `proto.go`. Callers send the packets and keep
//! the clock; this module decides what to answer and which requests completed.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use petrified::types::{Instant, PublicKey};
use serde_json::{Map, Value};

use crate::address::addr_for_key;
use crate::session::TYPE_SESSION_PROTO;

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
/// How long yggdrasil-go waits for a response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

/// What a request asks for, which is also the response type it waits on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Request {
	NodeInfo,
	DebugSelf,
	DebugPeers,
	DebugTree,
}

impl Request {
	/// The session packet that asks another node for this.
	pub fn packet(self) -> Vec<u8> {
		match self {
			Request::NodeInfo => vec![TYPE_SESSION_PROTO, PROTO_NODEINFO_REQUEST],
			Request::DebugSelf => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_SELF_REQUEST],
			Request::DebugPeers => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_PEERS_REQUEST],
			Request::DebugTree => vec![TYPE_SESSION_PROTO, PROTO_DEBUG, DEBUG_GET_TREE_REQUEST],
		}
	}
}

/// What a node tells others about itself when asked.
pub trait NodeView {
	fn public_key(&self) -> PublicKey;
	fn routing_entries(&self) -> u64;
	/// The keys of peers whose links are up.
	fn peer_keys(&self) -> Vec<PublicKey>;
	/// The keys in this node's view of the spanning tree.
	fn tree_keys(&self) -> Vec<PublicKey>;
	/// The largest session packet this node can send.
	fn mtu(&self) -> u64;
}

/// What to do with a protocol packet from another node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incoming {
	/// Send this session packet back to the sender.
	Reply(Vec<u8>),
	/// The sender answered a request.
	Response {
		request: Request,
		data: Vec<u8>,
	},
	Ignored,
}

/// Handles a protocol packet, given without its leading session type byte.
pub fn handle(packet: &[u8], nodeinfo: &[u8], node: &impl NodeView) -> Incoming {
	let Some((&kind, body)) = packet.split_first() else {
		return Incoming::Ignored;
	};
	match kind {
		PROTO_NODEINFO_REQUEST => {
			let mut reply = vec![TYPE_SESSION_PROTO, PROTO_NODEINFO_RESPONSE];
			reply.extend_from_slice(nodeinfo);
			Incoming::Reply(reply)
		}
		PROTO_NODEINFO_RESPONSE => Incoming::Response {
			request: Request::NodeInfo,
			data: body.to_vec(),
		},
		PROTO_DEBUG => handle_debug(body, node),
		_ => Incoming::Ignored,
	}
}

fn handle_debug(packet: &[u8], node: &impl NodeView) -> Incoming {
	let Some((&kind, body)) = packet.split_first() else {
		return Incoming::Ignored;
	};
	let reply = |kind: u8, data: &[u8]| {
		let mut reply = vec![TYPE_SESSION_PROTO, PROTO_DEBUG, kind];
		reply.extend_from_slice(data);
		Incoming::Reply(reply)
	};
	let response = |request: Request| Incoming::Response {
		request,
		data: body.to_vec(),
	};
	match kind {
		DEBUG_GET_SELF_REQUEST => {
			let mut fields = Map::new();
			fields.insert("key".into(), hex::encode(node.public_key().0).into());
			fields.insert(
				"routing_entries".into(),
				node.routing_entries().to_string().into(),
			);
			match crate::json::to_string(&fields) {
				Ok(json) => reply(DEBUG_GET_SELF_RESPONSE, json.as_bytes()),
				Err(_) => Incoming::Ignored,
			}
		}
		DEBUG_GET_PEERS_REQUEST => reply(
			DEBUG_GET_PEERS_RESPONSE,
			&pack_keys(&node.peer_keys(), node.mtu()),
		),
		DEBUG_GET_TREE_REQUEST => reply(
			DEBUG_GET_TREE_RESPONSE,
			&pack_keys(&node.tree_keys(), node.mtu()),
		),
		DEBUG_GET_SELF_RESPONSE => response(Request::DebugSelf),
		DEBUG_GET_PEERS_RESPONSE => response(Request::DebugPeers),
		DEBUG_GET_TREE_RESPONSE => response(Request::DebugTree),
		_ => Incoming::Ignored,
	}
}

/// Requests waiting for a response. A newer request to the same node
/// replaces an older one, as in Go. `T` is whatever the caller needs to
/// deliver the response, such as a channel.
#[derive(Debug)]
pub struct Pending<T> {
	requests: BTreeMap<(Request, PublicKey), (Instant, T)>,
}

impl<T> Default for Pending<T> {
	fn default() -> Self {
		Pending {
			requests: BTreeMap::new(),
		}
	}
}

impl<T> Pending<T> {
	/// Records a request sent at `now`, returning any older one it replaces.
	pub fn insert(
		&mut self,
		request: Request,
		key: PublicKey,
		now: Instant,
		waiter: T,
	) -> Option<T> {
		self.requests
			.insert((request, key), (now + REQUEST_TIMEOUT, waiter))
			.map(|(_, old)| old)
	}

	/// Takes the waiter for a response, if its request is still pending.
	pub fn complete(&mut self, request: Request, key: &PublicKey) -> Option<T> {
		self.requests
			.remove(&(request, *key))
			.map(|(_, waiter)| waiter)
	}

	/// Removes and returns the requests that timed out.
	pub fn expire(&mut self, now: Instant) -> Vec<(Request, PublicKey, T)> {
		let expired: Vec<(Request, PublicKey)> = self
			.requests
			.iter()
			.filter(|(_, (deadline, _))| *deadline <= now)
			.map(|(id, _)| *id)
			.collect();
		expired
			.into_iter()
			.filter_map(|(request, key)| {
				let (_, waiter) = self.requests.remove(&(request, key))?;
				Some((request, key, waiter))
			})
			.collect()
	}

	/// When the next request times out, if any is pending.
	pub fn next_deadline(&self) -> Option<Instant> {
		self.requests.values().map(|(deadline, _)| *deadline).min()
	}

	pub fn is_empty(&self) -> bool {
		self.requests.is_empty()
	}
}

/// Build details that nodeinfo includes unless it is private.
#[derive(Clone, Copy, Debug)]
pub struct BuildInfo<'a> {
	pub name: &'a str,
	pub version: &'a str,
	/// Named as Go's `runtime.GOOS` names it.
	pub platform: &'a str,
	/// Named as Go's `runtime.GOARCH` names it.
	pub arch: &'a str,
}

/// Builds a node's nodeinfo JSON from the configured map. With `build`, it adds
/// the build details, as yggdrasil-go does when nodeinfo privacy is off.
pub fn build_nodeinfo(
	given: &Map<String, Value>,
	build: Option<BuildInfo<'_>>,
) -> Result<Vec<u8>, String> {
	// Go marshals maps with sorted keys
	let mut nodeinfo: BTreeMap<String, Value> = given.clone().into_iter().collect();
	if let Some(build) = build {
		nodeinfo.insert("buildname".into(), build.name.into());
		nodeinfo.insert("buildversion".into(), build.version.into());
		nodeinfo.insert("buildplatform".into(), build.platform.into());
		nodeinfo.insert("buildarch".into(), build.arch.into());
	}
	let json = crate::json::to_string(&nodeinfo)
		.map_err(|error| format!("NodeInfo marshalling failed: {error}"))?;
	if json.len() > MAX_NODEINFO_SIZE {
		return Err("NodeInfo exceeds max length of 16384 bytes".into());
	}
	Ok(json.into_bytes())
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

/// Parses a hex public key, with yggdrasil-go's error messages.
pub fn parse_key(key: &str) -> Result<PublicKey, String> {
	let bytes = crate::go_hex::decode(key)?;
	let key: [u8; 32] = bytes
		.try_into()
		.map_err(|_| "invalid public key length".to_string())?;
	Ok(PublicKey(key))
}

/// The admin socket's answer for a nodeinfo response from `remote`.
pub fn nodeinfo_value(remote: &PublicKey, response: &[u8]) -> Result<Value, String> {
	let nodeinfo: Value = serde_json::from_slice(response).map_err(|error| error.to_string())?;
	Ok(Value::Object(Map::from_iter([(
		hex::encode(remote.0),
		nodeinfo,
	)])))
}

/// The admin socket's answer for a `debug_remoteGet*` response from `remote`.
pub fn debug_value(request: Request, remote: &PublicKey, response: &[u8]) -> Result<Value, String> {
	let value = match request {
		Request::DebugSelf => {
			serde_json::from_slice(response).map_err(|error| error.to_string())?
		}
		_ => unpack_keys(response),
	};
	let address = addr_for_key(remote).to_string();
	Ok(Value::Object(Map::from_iter([(address, value)])))
}

#[cfg(test)]
mod tests {
	use super::*;

	struct Node;

	impl NodeView for Node {
		fn public_key(&self) -> PublicKey {
			PublicKey([7; 32])
		}
		fn routing_entries(&self) -> u64 {
			3
		}
		fn peer_keys(&self) -> Vec<PublicKey> {
			vec![PublicKey([1; 32]), PublicKey([2; 32])]
		}
		fn tree_keys(&self) -> Vec<PublicKey> {
			vec![PublicKey([3; 32])]
		}
		fn mtu(&self) -> u64 {
			1000
		}
	}

	const BUILD: BuildInfo<'static> = BuildInfo {
		name: "yggdrasil",
		version: "1.0",
		platform: "linux",
		arch: "amd64",
	};

	#[test]
	fn nodeinfo_includes_build_details_unless_private() {
		let mut given = Map::new();
		given.insert("name".into(), "alice".into());
		let public: Value =
			serde_json::from_slice(&build_nodeinfo(&given, Some(BUILD)).unwrap()).unwrap();
		assert_eq!(public["name"], "alice");
		assert_eq!(public["buildname"], "yggdrasil");
		assert_eq!(
			build_nodeinfo(&given, None).unwrap(),
			br#"{"name":"alice"}"#
		);
	}

	#[test]
	fn rejects_oversized_nodeinfo() {
		let mut given = Map::new();
		given.insert("big".into(), "x".repeat(MAX_NODEINFO_SIZE).into());
		assert!(build_nodeinfo(&given, None).is_err());
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

	#[test]
	fn answers_requests_and_reports_responses() {
		// Each request, as another node receives it after the session type byte
		let Incoming::Reply(reply) = handle(&Request::NodeInfo.packet()[1..], b"{}", &Node) else {
			panic!("no nodeinfo reply");
		};
		assert_eq!(
			handle(&reply[1..], b"", &Node),
			Incoming::Response {
				request: Request::NodeInfo,
				data: b"{}".to_vec()
			}
		);
		let Incoming::Reply(reply) = handle(&Request::DebugPeers.packet()[1..], b"", &Node) else {
			panic!("no peers reply");
		};
		let Incoming::Response { request, data } = handle(&reply[1..], b"", &Node) else {
			panic!("reply not recognised");
		};
		assert_eq!(request, Request::DebugPeers);
		assert_eq!(
			debug_value(request, &PublicKey([9; 32]), &data)
				.unwrap()
				.as_object()
				.unwrap()
				.values()
				.next()
				.unwrap()["keys"]
				.as_array()
				.unwrap()
				.len(),
			2
		);
		assert_eq!(handle(&[], b"", &Node), Incoming::Ignored);
		assert_eq!(handle(&[42], b"", &Node), Incoming::Ignored);
	}

	#[test]
	fn pending_requests_complete_once_or_expire() {
		let mut pending = Pending::default();
		let start = Instant::from_duration(Duration::from_secs(100));
		let key = PublicKey([5; 32]);
		assert_eq!(pending.insert(Request::NodeInfo, key, start, 1), None);
		assert_eq!(pending.insert(Request::NodeInfo, key, start, 2), Some(1));
		assert_eq!(pending.complete(Request::DebugSelf, &key), None);
		assert_eq!(pending.complete(Request::NodeInfo, &key), Some(2));
		assert_eq!(pending.complete(Request::NodeInfo, &key), None);

		pending.insert(Request::DebugTree, key, start, 3);
		assert_eq!(pending.next_deadline(), Some(start + REQUEST_TIMEOUT));
		assert!(pending.expire(start + REQUEST_TIMEOUT / 2).is_empty());
		assert_eq!(
			pending.expire(start + REQUEST_TIMEOUT),
			vec![(Request::DebugTree, key, 3)]
		);
		assert!(pending.is_empty());
	}
}
