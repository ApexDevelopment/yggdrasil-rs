//! The Yggdrasil node: an Ironwood router with peer links, nodeinfo and debug requests.

pub mod link;
mod node;
mod proto;
pub mod tls;
pub mod uri;
pub mod version;

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use petrified::encrypted::PacketConn;
use petrified::network::{Config, DebugLookupInfo};
use petrified::types::{Error, PacketConn as _, PrivateKey, PublicKey, StdPlatform};
use serde_json::{Map, Value};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::address::{Address, Subnet, addr_for_key, subnet_for_key};
pub use link::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkError, LinkListener, LinkProtocol,
	LinkStream, Listener, PeerFilter,
};
use link::{LinkType, Links};
use node::{Node, TYPE_SESSION_TRAFFIC};
use tls::TlsConfigs;
use uri::PeerUri;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Ironwood's peer messages may be up to this size, enough for any IPv6 packet.
const PEER_MAX_MESSAGE_SIZE: u64 = 65535 * 2;

/// A peer to connect to at startup, optionally through a given source interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Peer {
	pub uri: String,
	pub source_interface: String,
}

/// Settings for [`Core::new`], equivalent to yggdrasil-go's `SetupOption`s.
#[derive(Clone, Default)]
pub struct Options {
	pub peers: Vec<Peer>,
	pub listen: Vec<String>,
	pub node_info: Map<String, Value>,
	pub node_info_privacy: bool,
	/// If not empty, only these keys may connect to non-multicast listeners.
	pub allowed_public_keys: Vec<PublicKey>,
	/// Returns false for addresses that must never be dialed.
	pub peer_filter: Option<PeerFilter>,
	pub group_password: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfInfo {
	pub key: PublicKey,
	pub routing_entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
	pub uri: String,
	pub up: bool,
	pub inbound: bool,
	pub last_error: Option<String>,
	pub last_error_time: Option<SystemTime>,
	/// Known once the link is up and registered with the router.
	pub key: Option<PublicKey>,
	pub port: u64,
	pub priority: u8,
	pub cost: u64,
	pub rx_bytes: u64,
	pub tx_bytes: u64,
	pub rx_rate: u64,
	pub tx_rate: u64,
	pub uptime: Duration,
	pub latency: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntryInfo {
	pub key: PublicKey,
	pub parent: PublicKey,
	pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEntryInfo {
	pub key: PublicKey,
	pub path: Vec<u64>,
	pub sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
	pub key: PublicKey,
	pub rx_bytes: u64,
	pub tx_bytes: u64,
	pub uptime: Duration,
}

type PathNotify = Arc<dyn Fn(PublicKey) + Send + Sync>;
type LookupLogger = Arc<dyn Fn(&DebugLookupInfo) + Send + Sync>;

pub(crate) struct CoreInner {
	node: Arc<Node>,
	secret: PrivateKey,
	public: PublicKey,
	links: Links,
	proto: proto::Proto,
	allowed_public_keys: HashSet<PublicKey>,
	path_notify: Mutex<Option<PathNotify>>,
	lookup_logger: Arc<Mutex<Option<LookupLogger>>>,
	cancel: CancellationToken,
}

/// A running Yggdrasil node. Cloning gives another handle to the same node.
///
/// Must be created and used inside a tokio runtime.
#[derive(Clone)]
pub struct Core {
	inner: Arc<CoreInner>,
}

impl Core {
	pub async fn new(secret: PrivateKey, options: Options) -> Result<Core, BoxError> {
		log::info!("Build name: {}", crate::version::build_name());
		log::info!("Build version: {}", crate::version::build_version());
		let public = secret.public_key();
		let tls = TlsConfigs::new(&secret)
			.map_err(|error| format!("error generating TLS config: {error}"))?;
		let (path_sender, path_receiver) = mpsc::unbounded_channel();
		let config = Config::default()
			.with_bloom_transform(|key| subnet_for_key(key).get_key())
			.with_peer_max_message_size(PEER_MAX_MESSAGE_SIZE)
			.with_path_notify(move |key| {
				let _ = path_sender.send(*key);
			});
		let mut conn = PacketConn::new_with_password(
			&secret,
			&options.group_password,
			StdPlatform::new(),
			config,
		)
		.map_err(|error| format!("error creating encryption: {error}"))?;
		let lookup_logger: Arc<Mutex<Option<LookupLogger>>> = Arc::default();
		let logger = lookup_logger.clone();
		conn.network_mut().set_debug_lookup_logger(move |info| {
			let logger = logger
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner())
				.clone();
			if let Some(logger) = logger {
				logger(info);
			}
		});
		let (proto_sender, proto_receiver) = mpsc::unbounded_channel();
		let node = Node::start(conn, PEER_MAX_MESSAGE_SIZE as usize, proto_sender);
		let nodeinfo = proto::build_nodeinfo(&options.node_info, options.node_info_privacy)
			.map_err(|error| format!("error setting node info: {error}"))?;
		let inner = Arc::new(CoreInner {
			node,
			secret,
			public,
			links: Links::new(LinkContext {
				tls,
				peer_filter: options.peer_filter.clone(),
			}),
			proto: proto::Proto::default(),
			allowed_public_keys: options.allowed_public_keys.iter().copied().collect(),
			path_notify: Mutex::new(None),
			lookup_logger,
			cancel: CancellationToken::new(),
		});
		inner.proto.set_nodeinfo(nodeinfo);
		tokio::spawn(proto::run(inner.clone(), proto_receiver));
		tokio::spawn(run_path_notify(inner.clone(), path_receiver));
		tokio::spawn(Links::run_rate_updates(inner.clone()));
		let core = Core { inner };
		for peer in &options.peers {
			match core.add_peer(&peer.uri, &peer.source_interface) {
				Ok(()) | Err(LinkError::AlreadyConfigured) => {}
				Err(error) => {
					core.stop();
					return Err(
						format!("failed to apply configuration option Peer: {error}").into(),
					);
				}
			}
		}
		let listen: HashSet<&String> = options.listen.iter().collect();
		for addr in listen {
			if let Err(error) = core.listen(addr, "").await {
				log::error!("Failed to start listener {addr:?}: {error}");
			}
		}
		Ok(core)
	}

	pub fn public_key(&self) -> PublicKey {
		self.inner.public
	}

	pub fn private_key(&self) -> &PrivateKey {
		&self.inner.secret
	}

	/// This node's /128 address.
	pub fn address(&self) -> Address {
		addr_for_key(&self.inner.public)
	}

	/// This node's routed /64 subnet.
	pub fn subnet(&self) -> Subnet {
		subnet_for_key(&self.inner.public)
	}

	/// The largest packet [`Core::write_to`] accepts.
	pub fn mtu(&self) -> u64 {
		self.inner.mtu()
	}

	/// Waits for the next packet from another node. Fails once the node is stopped.
	pub async fn recv(&self) -> Result<(PublicKey, Vec<u8>), Error> {
		self.inner.node.recv().await.ok_or(Error::Closed)
	}

	/// Like [`Core::recv`], copying as much of the packet as fits into `buf`.
	pub async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, PublicKey), Error> {
		let (from, packet) = self.recv().await?;
		let n = packet.len().min(buf.len());
		buf[..n].copy_from_slice(&packet[..n]);
		Ok((n, from))
	}

	/// Sends a packet to the node with key `dest`.
	pub fn write_to(&self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		let mut packet = Vec::with_capacity(data.len() + 1);
		packet.push(TYPE_SESSION_TRAFFIC);
		packet.extend_from_slice(data);
		self.inner
			.node
			.write_to(&packet, dest)
			.map(|n| n.saturating_sub(1))
	}

	/// Looks up the node owning a (possibly partial) key, as derived from an address.
	pub fn send_lookup(&self, partial: &PublicKey) {
		self.inner
			.node
			.update(|state| state.conn.send_lookup(partial));
	}

	/// Calls `notify` whenever a path to a node is found or updated.
	pub fn set_path_notify(&self, notify: impl Fn(PublicKey) + Send + Sync + 'static) {
		*self
			.inner
			.path_notify
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(notify));
	}

	/// Calls `logger` for every lookup this node handles.
	pub fn set_lookup_logger(&self, logger: impl Fn(&DebugLookupInfo) + Send + Sync + 'static) {
		*self
			.inner
			.lookup_logger
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(logger));
	}

	pub fn get_self(&self) -> SelfInfo {
		self.inner.get_self()
	}

	/// Every configured or connected peer link.
	pub fn get_peers(&self) -> Vec<PeerInfo> {
		self.inner.get_peers()
	}

	pub fn get_tree(&self) -> Vec<TreeEntryInfo> {
		self.inner.get_tree()
	}

	pub fn get_paths(&self) -> Vec<PathEntryInfo> {
		self.inner.node.inspect(|state| {
			state
				.conn
				.network()
				.debug()
				.get_paths()
				.into_iter()
				.map(|path| PathEntryInfo {
					key: path.key,
					path: path.path,
					sequence: path.sequence,
				})
				.collect()
		})
	}

	pub fn get_sessions(&self) -> Vec<SessionInfo> {
		self.inner.node.inspect(|state| {
			state
				.conn
				.get_sessions()
				.into_iter()
				.map(|session| SessionInfo {
					key: session.key,
					rx_bytes: session.rx,
					tx_bytes: session.tx,
					uptime: session.uptime,
				})
				.collect()
		})
	}

	/// Starts a listener for incoming links, e.g. on `tls://0.0.0.0:0`.
	/// A link-local address needs its interface as `sintf`.
	pub async fn listen(&self, uri: &str, sintf: &str) -> Result<Listener, LinkError> {
		let uri = PeerUri::parse(uri).map_err(|error| LinkError::Other(error.to_string()))?;
		link::listen(&self.inner, &uri, sintf, false).await
	}

	/// Like [`Core::listen`], but ignores `AllowedPublicKeys`, as for multicast.
	pub async fn listen_local(&self, uri: &str, sintf: &str) -> Result<Listener, LinkError> {
		let uri = PeerUri::parse(uri).map_err(|error| LinkError::Other(error.to_string()))?;
		link::listen(&self.inner, &uri, sintf, true).await
	}

	/// Adds a peer that is reconnected whenever its link drops.
	pub fn add_peer(&self, uri: &str, sintf: &str) -> Result<(), LinkError> {
		let uri = PeerUri::parse(uri)
			.map_err(|error| LinkError::Other(format!("unable to parse peering URI: {error}")))?;
		link::add(&self.inner, &uri, sintf, LinkType::Persistent)
	}

	/// Removes a peer added with [`Core::add_peer`] and closes its link.
	pub fn remove_peer(&self, uri: &str, sintf: &str) -> Result<(), LinkError> {
		let uri = PeerUri::parse(uri)
			.map_err(|error| LinkError::Other(format!("unable to parse peering URI: {error}")))?;
		link::remove(&self.inner, &uri, sintf)
	}

	/// Connects to a peer once, without reconnecting.
	pub fn call_peer(&self, uri: &str, sintf: &str) -> Result<(), LinkError> {
		let uri = PeerUri::parse(uri).map_err(|error| LinkError::Other(error.to_string()))?;
		link::add(&self.inner, &uri, sintf, LinkType::Ephemeral)
	}

	/// Makes every backing-off peer retry immediately.
	pub fn retry_peers_now(&self) {
		self.inner.links.retry_now();
	}

	/// Adds a transport for peering URIs with the given scheme, or replaces a built-in one.
	pub fn register_link_protocol(&self, scheme: &str, protocol: Arc<dyn LinkProtocol>) {
		self.inner.links.register(scheme, protocol);
	}

	/// The admin `getNodeInfo` request.
	pub async fn get_node_info(&self, key: &str) -> Result<Value, String> {
		self.inner.get_node_info(key).await
	}

	/// The admin `debug_remoteGetSelf` request.
	pub async fn remote_get_self(&self, key: &str) -> Result<Value, String> {
		self.inner.remote_get_self(key).await
	}

	/// The admin `debug_remoteGetPeers` request.
	pub async fn remote_get_peers(&self, key: &str) -> Result<Value, String> {
		self.inner.remote_get_peers(key).await
	}

	/// The admin `debug_remoteGetTree` request.
	pub async fn remote_get_tree(&self, key: &str) -> Result<Value, String> {
		self.inner.remote_get_tree(key).await
	}

	pub fn is_stopped(&self) -> bool {
		self.inner.cancel.is_cancelled()
	}

	/// Closes every link and listener, and stops the node.
	pub fn stop(&self) {
		log::info!("Stopping...");
		self.inner.cancel.cancel();
		self.inner.links.shutdown();
		self.inner.node.close();
		log::info!("Stopped");
	}
}

impl CoreInner {
	fn mtu(&self) -> u64 {
		const SESSION_TYPE_OVERHEAD: u64 = 1;
		let mtu = self.node.inspect(|state| state.conn.mtu());
		(mtu - SESSION_TYPE_OVERHEAD).min(65535)
	}

	fn is_allowed(&self, key: &PublicKey) -> bool {
		self.allowed_public_keys.is_empty() || self.allowed_public_keys.contains(key)
	}

	fn get_self(&self) -> SelfInfo {
		let info = self
			.node
			.inspect(|state| state.conn.network().debug().get_self());
		SelfInfo {
			key: info.key,
			routing_entries: info.routing_entries,
		}
	}

	fn get_tree(&self) -> Vec<TreeEntryInfo> {
		self.node.inspect(|state| {
			state
				.conn
				.network()
				.debug()
				.get_tree()
				.into_iter()
				.map(|entry| TreeEntryInfo {
					key: entry.key,
					parent: entry.parent,
					sequence: entry.sequence,
				})
				.collect()
		})
	}

	fn get_peers(&self) -> Vec<PeerInfo> {
		let routed: HashMap<_, _> = self.node.inspect(|state| {
			state
				.conn
				.network()
				.debug()
				.get_peers()
				.into_iter()
				.map(|peer| (peer.peer, peer))
				.collect()
		});
		self.links
			.snapshot()
			.into_iter()
			.map(|(uri, link)| {
				let status = link.status();
				let mut info = PeerInfo {
					uri,
					up: false,
					inbound: false,
					last_error: status.error.clone(),
					last_error_time: status.error_time,
					key: None,
					port: 0,
					priority: 0,
					cost: 0,
					rx_bytes: 0,
					tx_bytes: 0,
					rx_rate: 0,
					tx_rate: 0,
					uptime: Duration::ZERO,
					latency: Duration::ZERO,
				};
				if let Some(conn) = &status.conn {
					use std::sync::atomic::Ordering::Relaxed;
					info.up = true;
					info.inbound = link.link_type == LinkType::Incoming;
					info.rx_bytes = conn.rx.load(Relaxed);
					info.tx_bytes = conn.tx.load(Relaxed);
					info.rx_rate = conn.rx_rate.load(Relaxed);
					info.tx_rate = conn.tx_rate.load(Relaxed);
					info.uptime = conn.up.elapsed();
					let peer_id = *conn
						.peer
						.lock()
						.unwrap_or_else(|poisoned| poisoned.into_inner());
					if let Some(peer) = peer_id.and_then(|id| routed.get(&id)) {
						info.key = Some(peer.key);
						info.port = peer.port;
						info.priority = peer.priority;
						info.latency = peer.latency;
						info.cost = peer.cost;
					}
				}
				info
			})
			.collect()
	}
}

async fn run_path_notify(core: Arc<CoreInner>, mut keys: mpsc::UnboundedReceiver<PublicKey>) {
	loop {
		let key = tokio::select! {
			key = keys.recv() => key,
			_ = core.cancel.cancelled() => None,
		};
		let Some(key) = key else {
			return;
		};
		let notify = core
			.path_notify
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.clone();
		if let Some(notify) = notify {
			notify(key);
		}
	}
}

/// Matches nothing in the Yggdrasil range, so that peering never happens over Yggdrasil itself.
pub fn default_peer_filter() -> PeerFilter {
	Arc::new(|ip: IpAddr| match ip {
		IpAddr::V6(v6) => v6.octets()[0] & 0xfe != 0x02,
		IpAddr::V4(_) => true,
	})
}
