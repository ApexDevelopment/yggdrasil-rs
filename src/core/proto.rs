//! Answers nodeinfo and debug requests from other nodes and sends this node's
//! own, around the state machine in [`yggdrasil_proto::requests`].

use std::sync::{Arc, Mutex};

use petrified::types::PublicKey;
use serde_json::{Map, Value};
use tokio::sync::{mpsc, oneshot};
use yggdrasil_proto::requests::{
	self, BuildInfo, Incoming, NodeView, Pending, REQUEST_TIMEOUT, Request,
};

use super::CoreInner;
use crate::version;

#[derive(Default)]
pub(crate) struct Proto {
	nodeinfo: Mutex<Vec<u8>>,
	pending: Mutex<Pending<oneshot::Sender<Vec<u8>>>>,
}

/// Builds this node's nodeinfo JSON from the configured map.
pub fn build_nodeinfo(given: &Map<String, Value>, privacy: bool) -> Result<Vec<u8>, String> {
	let build = BuildInfo {
		name: version::build_name(),
		version: version::build_version(),
		platform: version::build_platform(),
		arch: version::build_arch(),
	};
	requests::build_nodeinfo(given, (!privacy).then_some(build))
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

	fn pending(&self) -> std::sync::MutexGuard<'_, Pending<oneshot::Sender<Vec<u8>>>> {
		self.pending
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}
}

impl NodeView for CoreInner {
	fn public_key(&self) -> PublicKey {
		self.public
	}

	fn routing_entries(&self) -> u64 {
		self.get_self().routing_entries
	}

	fn peer_keys(&self) -> Vec<PublicKey> {
		self.get_peers()
			.into_iter()
			.filter_map(|peer| peer.key)
			.collect()
	}

	fn tree_keys(&self) -> Vec<PublicKey> {
		self.get_tree().into_iter().map(|entry| entry.key).collect()
	}

	fn mtu(&self) -> u64 {
		CoreInner::mtu(self)
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
		match requests::handle(&packet, &core.proto.nodeinfo(), core.as_ref()) {
			Incoming::Reply(reply) => {
				let _ = core.node.write_to(&reply, &from);
			}
			Incoming::Response { request, data } => {
				if let Some(waiter) = core.proto.pending().complete(request, &from) {
					let _ = waiter.send(data);
				}
			}
			Incoming::Ignored => {}
		}
	}
}

impl CoreInner {
	async fn request(&self, request: Request, key: PublicKey) -> Option<Vec<u8>> {
		let (sender, receiver) = oneshot::channel();
		{
			let now = self.now();
			let mut pending = self.proto.pending();
			pending.expire(now);
			pending.insert(request, key, now, sender);
		}
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
		crate::go_hex::decode(key)
			.map_err(|error| format!("failed to decode public key: {error}"))?;
		let remote = requests::parse_key(key)?;
		let response = self
			.request(Request::NodeInfo, remote)
			.await
			.ok_or("timed out waiting for response")?;
		requests::nodeinfo_value(&remote, &response)
	}

	/// The admin `debug_remoteGet*` requests.
	async fn remote_debug(&self, request: Request, key: &str) -> Result<Value, String> {
		let remote = requests::parse_key(key)?;
		let response = self.request(request, remote).await.ok_or("timeout")?;
		requests::debug_value(request, &remote, &response)
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
	fn nodeinfo_reports_this_build() {
		let nodeinfo: Value =
			serde_json::from_slice(&build_nodeinfo(&Map::new(), false).unwrap()).unwrap();
		assert_eq!(nodeinfo["buildname"], version::build_name());
		assert_eq!(nodeinfo["buildarch"], version::build_arch());
	}
}
