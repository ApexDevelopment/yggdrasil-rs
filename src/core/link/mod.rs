//! Peer links: dialing, listening, the link handshake, and reconnecting.
//!
//! Each transport implements [`LinkProtocol`]. The built-in ones mirror
//! yggdrasil-go (`tcp`, `tls`, `unix`, `socks`, `sockstls`, `quic`, `ws` and
//! `wss`), and [`crate::core::Core::register_link_protocol`] adds others.

mod counted;
mod lazy;
mod quic;
mod socks;
mod tcp;
mod tls;
#[cfg(unix)]
mod unix;
mod ws;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

use petrified::types::{PeerId, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::CoreInner;
use super::node::ConnError;
use super::tls::TlsConfigs;
use super::uri::{PeerUri, parse_go_duration, split_host_port};
use super::version::{MAX_PASSWORD_LEN, Metadata, read_metadata};
use crate::address::addr_for_key;

pub use counted::Counted;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A reliable, ordered byte stream to a peer.
pub trait LinkStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> LinkStream for T {}

/// A freshly opened stream, before the link handshake.
pub struct LinkConnection {
	pub stream: Box<dyn LinkStream>,
	/// For logs, e.g. `127.0.0.1:1234`.
	pub local_addr: String,
	/// For logs and the URIs of incoming links.
	pub remote_addr: String,
}

/// Everything a dial needs beyond the URI.
pub struct DialRequest<'a> {
	pub uri: &'a PeerUri,
	/// The source interface, if the peer was configured with one.
	pub sintf: &'a str,
	/// The TLS server name, from the `sni` query or the URI's hostname.
	pub tls_sni: Option<&'a str>,
}

/// A transport that can carry peer links.
pub trait LinkProtocol: Send + Sync + 'static {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>>;

	fn listen<'a>(
		&'a self,
		ctx: &'a LinkContext,
		uri: &'a PeerUri,
		sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>>;
}

pub trait LinkListener: Send + 'static {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>>;
	fn local_addr(&self) -> String;
}

pub type PeerFilter = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Shared state for transports.
pub struct LinkContext {
	pub tls: TlsConfigs,
	pub peer_filter: Option<PeerFilter>,
}

impl LinkContext {
	/// Resolves a URI's host to the addresses worth dialing, like yggdrasil-go's `findSuitableIP`.
	/// Link-local addresses get their zone from the host (`fe80::1%eth0`) or `sintf`.
	pub async fn suitable_addresses(
		&self,
		uri: &PeerUri,
		sintf: &str,
	) -> io::Result<(String, Vec<SocketAddr>)> {
		let (host, port) = uri.host_port().map_err(io::Error::other)?;
		let (name, zone) = match host.split_once('%') {
			Some((name, zone)) => (name.to_string(), Some(zone.to_string())),
			None => (host.clone(), None),
		};
		let zone = if sintf.is_empty() {
			zone
		} else {
			Some(sintf.to_string())
		};
		let resolved = tokio::net::lookup_host((name.as_str(), port)).await?;
		let mut addrs = Vec::new();
		for mut addr in resolved {
			let ip = addr.ip();
			if ip.is_unspecified() || ip.is_multicast() {
				continue;
			}
			if self.peer_filter.as_ref().is_some_and(|filter| !filter(ip)) {
				continue;
			}
			if let SocketAddr::V6(v6) = &mut addr
				&& v6.ip().is_unicast_link_local()
			{
				let Some(zone) = &zone else {
					return Err(io::Error::other("link-local address requires a zone"));
				};
				v6.set_scope_id(interface_index(zone)?);
			}
			addrs.push(addr);
		}
		if addrs.is_empty() {
			return Err(io::Error::other(LinkError::NoSuitableIps.to_string()));
		}
		Ok((host, addrs))
	}
}

/// Tries each address in turn and returns the first that connects.
pub async fn first_success<T, F, Fut>(addrs: Vec<SocketAddr>, mut attempt: F) -> io::Result<T>
where
	F: FnMut(SocketAddr) -> Fut,
	Fut: Future<Output = io::Result<T>>,
{
	let mut last_error = io::Error::other(LinkError::NoSuitableIps.to_string());
	for addr in addrs {
		match attempt(addr).await {
			Ok(result) => return Ok(result),
			Err(error) => {
				log::debug!("Dialling {addr} reported error: {error}");
				last_error = error;
			}
		}
	}
	Err(last_error)
}

/// The index of a network interface, given its name or its index as text.
pub fn interface_index(name: &str) -> io::Result<u32> {
	if let Ok(index) = name.parse() {
		return Ok(index);
	}
	netdev::get_interfaces()
		.into_iter()
		.find(|iface| iface.name == name)
		.map(|iface| iface.index)
		.ok_or_else(|| io::Error::other(format!("interface {name:?} not found")))
}

fn interface_name(index: u32) -> Option<String> {
	netdev::get_interfaces()
		.into_iter()
		.find(|iface| iface.index == index)
		.map(|iface| iface.name)
}

/// Formats an address like Go does, naming the zone of link-local addresses.
pub fn format_socket_addr(addr: &SocketAddr) -> String {
	match addr {
		SocketAddr::V6(v6) if v6.scope_id() != 0 => {
			let zone = interface_name(v6.scope_id()).unwrap_or_else(|| v6.scope_id().to_string());
			format!("[{}%{}]:{}", v6.ip(), zone, v6.port())
		}
		_ => addr.to_string(),
	}
}

/// Parses `host:port`, where an IPv6 host may carry a zone name, into a socket address.
pub fn parse_socket_addr(hostport: &str) -> io::Result<SocketAddr> {
	let (host, port) = split_host_port(hostport).map_err(io::Error::other)?;
	let (ip, zone) = match host.split_once('%') {
		Some((ip, zone)) => (ip, Some(zone)),
		None => (host.as_str(), None),
	};
	let ip: IpAddr = if ip.is_empty() {
		IpAddr::from([0u8; 16])
	} else {
		ip.parse().map_err(io::Error::other)?
	};
	let mut addr = SocketAddr::new(ip, port);
	if let (SocketAddr::V6(v6), Some(zone)) = (&mut addr, zone) {
		v6.set_scope_id(interface_index(zone)?);
	}
	Ok(addr)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
	AlreadyConfigured,
	NotConfigured,
	PriorityInvalid,
	PinnedKeyInvalid,
	PasswordInvalid,
	UnrecognisedSchema,
	MaxBackoffInvalid,
	NoSuitableIps,
	ToSelf,
	Other(String),
}

impl fmt::Display for LinkError {
	/// Uses the same messages as yggdrasil-go.
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			LinkError::AlreadyConfigured => "peer is already configured",
			LinkError::NotConfigured => "peer is not configured",
			LinkError::PriorityInvalid => "priority value is invalid",
			LinkError::PinnedKeyInvalid => "pinned public key is invalid",
			LinkError::PasswordInvalid => "invalid password supplied",
			LinkError::UnrecognisedSchema => "link schema unknown",
			LinkError::MaxBackoffInvalid => "max backoff duration invalid",
			LinkError::NoSuitableIps => "peer has no suitable addresses",
			LinkError::ToSelf => "node cannot connect to self",
			LinkError::Other(message) => message,
		})
	}
}

impl std::error::Error for LinkError {}

impl From<io::Error> for LinkError {
	fn from(error: io::Error) -> Self {
		LinkError::Other(error.to_string())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkType {
	/// Statically configured.
	Persistent,
	/// Discovered by multicast.
	Ephemeral,
	Incoming,
}

const DEFAULT_BACKOFF_LIMIT: Duration = Duration::from_secs(1 << 12);
const MINIMUM_BACKOFF_LIMIT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Default)]
struct LinkOptions {
	pinned_keys: HashSet<PublicKey>,
	priority: u8,
	tls_sni: Option<String>,
	password: Vec<u8>,
	max_backoff: Duration,
}

impl LinkOptions {
	/// The options shared by dialing and listening.
	fn common(uri: &PeerUri) -> Result<Self, LinkError> {
		let mut options = LinkOptions {
			max_backoff: DEFAULT_BACKOFF_LIMIT,
			..Default::default()
		};
		if let Some(priority) = uri.query_value("priority") {
			options.priority = priority.parse().map_err(|_| LinkError::PriorityInvalid)?;
		}
		if let Some(password) = uri.query_value("password") {
			if password.len() > MAX_PASSWORD_LEN {
				return Err(LinkError::PasswordInvalid);
			}
			options.password = password.as_bytes().to_vec();
		}
		Ok(options)
	}

	fn for_dial(uri: &PeerUri) -> Result<Self, LinkError> {
		let mut options = Self::common(uri)?;
		for key in uri.query_values("key") {
			let mut bytes = [0u8; 32];
			// Like Go, a short key is zero-padded rather than rejected
			let decoded = hex::decode(key).map_err(|_| LinkError::PinnedKeyInvalid)?;
			let len = decoded.len().min(32);
			bytes[..len].copy_from_slice(&decoded[..len]);
			options.pinned_keys.insert(PublicKey(bytes));
		}
		if let Some(backoff) = uri.query_value("maxbackoff") {
			options.max_backoff = parse_go_duration(backoff)
				.filter(|duration| *duration >= MINIMUM_BACKOFF_LIMIT)
				.ok_or(LinkError::MaxBackoffInvalid)?;
		}
		// SNI must be a hostname, never an IP literal
		options.tls_sni = uri
			.query_value("sni")
			.filter(|sni| sni.parse::<IpAddr>().is_err())
			.map(str::to_string)
			.or_else(|| {
				let (host, _) = uri.host_port().ok()?;
				(host.parse::<IpAddr>().is_err() && !host.contains('%')).then_some(host)
			});
		Ok(options)
	}
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct LinkInfo {
	uri: String,
	sintf: String,
}

/// Traffic counters and controls for one connected link.
pub(crate) struct LinkConn {
	pub rx: AtomicU64,
	pub tx: AtomicU64,
	pub rx_rate: AtomicU64,
	pub tx_rate: AtomicU64,
	last_rx: AtomicU64,
	last_tx: AtomicU64,
	pub up: Instant,
	pub peer: Mutex<Option<PeerId>>,
	stop: CancellationToken,
}

impl LinkConn {
	fn new() -> Self {
		LinkConn {
			rx: AtomicU64::new(0),
			tx: AtomicU64::new(0),
			rx_rate: AtomicU64::new(0),
			tx_rate: AtomicU64::new(0),
			last_rx: AtomicU64::new(0),
			last_tx: AtomicU64::new(0),
			up: Instant::now(),
			peer: Mutex::new(None),
			stop: CancellationToken::new(),
		}
	}

	fn update_rates(&self) {
		let rx = self.rx.load(Ordering::Relaxed);
		let tx = self.tx.load(Ordering::Relaxed);
		self.rx_rate.store(
			rx - self.last_rx.swap(rx, Ordering::Relaxed),
			Ordering::Relaxed,
		);
		self.tx_rate.store(
			tx - self.last_tx.swap(tx, Ordering::Relaxed),
			Ordering::Relaxed,
		);
	}
}

#[derive(Default)]
pub(crate) struct LinkStatus {
	pub conn: Option<Arc<LinkConn>>,
	pub error: Option<String>,
	pub error_time: Option<SystemTime>,
}

pub(crate) struct Link {
	pub link_type: LinkType,
	kick: Notify,
	cancel: CancellationToken,
	pub status: Mutex<LinkStatus>,
}

impl Link {
	fn new(link_type: LinkType, parent: &CancellationToken) -> Self {
		Link {
			link_type,
			kick: Notify::new(),
			cancel: parent.child_token(),
			status: Mutex::new(LinkStatus::default()),
		}
	}

	pub fn status(&self) -> std::sync::MutexGuard<'_, LinkStatus> {
		self.status
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	fn record_error(&self, error: String) {
		let mut status = self.status();
		status.conn = None;
		status.error = Some(error);
		status.error_time = Some(SystemTime::now());
	}
}

/// A running listener. Dropping it does not stop it; call [`Listener::cancel`].
#[derive(Clone)]
pub struct Listener {
	addr: String,
	cancel: CancellationToken,
}

impl Listener {
	/// The bound address, e.g. `127.0.0.1:43210`.
	pub fn local_addr(&self) -> &str {
		&self.addr
	}

	pub fn cancel(&self) {
		self.cancel.cancel();
	}
}

pub(crate) struct Links {
	links: Mutex<HashMap<LinkInfo, Arc<Link>>>,
	protocols: RwLock<HashMap<String, Arc<dyn LinkProtocol>>>,
	pub ctx: LinkContext,
}

impl Links {
	pub fn new(ctx: LinkContext) -> Self {
		let mut protocols: HashMap<String, Arc<dyn LinkProtocol>> = HashMap::new();
		protocols.insert("tcp".into(), Arc::new(tcp::Tcp));
		protocols.insert("tls".into(), Arc::new(tls::Tls));
		protocols.insert("socks".into(), Arc::new(socks::Socks { tls: false }));
		protocols.insert("sockstls".into(), Arc::new(socks::Socks { tls: true }));
		#[cfg(unix)]
		protocols.insert("unix".into(), Arc::new(unix::Unix));
		protocols.insert("quic".into(), Arc::new(quic::Quic));
		protocols.insert("ws".into(), Arc::new(ws::WebSocket { secure: false }));
		protocols.insert("wss".into(), Arc::new(ws::WebSocket { secure: true }));
		Links {
			links: Mutex::new(HashMap::new()),
			protocols: RwLock::new(protocols),
			ctx,
		}
	}

	pub fn register(&self, scheme: &str, protocol: Arc<dyn LinkProtocol>) {
		self.protocols
			.write()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.insert(scheme.to_ascii_lowercase(), protocol);
	}

	fn protocol(&self, scheme: &str) -> Result<Arc<dyn LinkProtocol>, LinkError> {
		self.protocols
			.read()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(scheme)
			.cloned()
			.ok_or(LinkError::UnrecognisedSchema)
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<LinkInfo, Arc<Link>>> {
		self.links
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Every link with its URI and source interface.
	pub fn snapshot(&self) -> Vec<(String, Arc<Link>)> {
		self.lock()
			.iter()
			.map(|(info, link)| (info.uri.clone(), link.clone()))
			.collect()
	}

	pub fn retry_now(&self) {
		for link in self.lock().values() {
			link.kick.notify_waiters();
		}
	}

	fn remove_if_current(&self, info: &LinkInfo, link: &Arc<Link>) {
		let mut links = self.lock();
		if links
			.get(info)
			.is_some_and(|current| Arc::ptr_eq(current, link))
		{
			links.remove(info);
		}
	}

	/// Updates the per-second traffic rates of every link, until `stop`.
	pub async fn run_rate_updates(core: Arc<CoreInner>) {
		let mut interval = tokio::time::interval(Duration::from_secs(1));
		loop {
			tokio::select! {
				_ = interval.tick() => {}
				_ = core.cancel.cancelled() => return,
			}
			for (_, link) in core.links.snapshot() {
				if let Some(conn) = &link.status().conn {
					conn.update_rates();
				}
			}
		}
	}

	pub fn shutdown(&self) {
		for link in self.lock().values() {
			link.cancel.cancel();
			if let Some(conn) = &link.status().conn {
				conn.stop.cancel();
			}
		}
	}
}

/// Adds a link that connects (and, if persistent, keeps reconnecting) to `uri`.
pub(crate) fn add(
	core: &Arc<CoreInner>,
	uri: &PeerUri,
	sintf: &str,
	link_type: LinkType,
) -> Result<(), LinkError> {
	core.links.protocol(&uri.scheme)?;
	let info = LinkInfo {
		uri: uri.without_query().to_string(),
		sintf: sintf.to_string(),
	};
	let options = LinkOptions::for_dial(uri)?;
	let link = {
		let mut links = core.links.lock();
		if let Some(existing) = links.get(&info) {
			existing.kick.notify_waiters();
			return Err(LinkError::AlreadyConfigured);
		}
		let link = Arc::new(Link::new(link_type, &core.cancel));
		links.insert(info.clone(), link.clone());
		link
	};
	let task_core = core.clone();
	let uri = uri.clone();
	core.runtime.spawn(async move {
		let core = task_core;
		run_outbound(&core, &uri, &info, &options, &link).await;
		core.links.remove_if_current(&info, &link);
	});
	Ok(())
}

async fn run_outbound(
	core: &Arc<CoreInner>,
	uri: &PeerUri,
	info: &LinkInfo,
	options: &LinkOptions,
	link: &Arc<Link>,
) {
	let persistent = link.link_type == LinkType::Persistent;
	// Consecutive failures; negative means never retry on a timer
	let mut backoff: i32 = 0;
	loop {
		if link.cancel.is_cancelled() {
			return;
		}
		let connected = tokio::select! {
			connected = connect(core, uri, info, options) => connected,
			_ = link.cancel.cancelled() => return,
		};
		let conn = match connected {
			Ok(conn) => conn,
			Err(error) => {
				if persistent {
					link.record_error(error.to_string());
					if wait_backoff(link, &mut backoff, options.max_backoff).await {
						continue;
					}
				}
				return;
			}
		};
		let link_conn = Arc::new(LinkConn::new());
		{
			let mut status = link.status();
			if status.conn.is_some() {
				// Another connection came up in the meantime
				return;
			}
			status.conn = Some(link_conn.clone());
			status.error = None;
			status.error_time = Some(SystemTime::now());
		}
		let handshake_done = AtomicBool::new(false);
		let result = handler(
			core,
			link.link_type,
			options,
			conn,
			&link_conn,
			Some(&handshake_done),
			false,
		)
		.await;
		if handshake_done.load(Ordering::Relaxed) {
			backoff = 0;
		}
		match &result {
			Err(LinkError::ToSelf) => backoff = -1,
			Err(error) => log::debug!("Link {} error: {error}", uri.host),
			Ok(()) => {}
		}
		link_conn.stop.cancel();
		link.record_error(match result {
			Ok(()) => "remote side closed the connection".to_string(),
			Err(error) => error.to_string(),
		});
		if !persistent || !wait_backoff(link, &mut backoff, options.max_backoff).await {
			return;
		}
	}
}

/// Waits before the next attempt. Returns false if the link was cancelled.
async fn wait_backoff(link: &Link, backoff: &mut i32, max_backoff: Duration) -> bool {
	if (0..32).contains(backoff) {
		*backoff += 1;
	}
	let timeout = async {
		if *backoff < 0 {
			std::future::pending::<()>().await;
		}
		let delay = Duration::from_secs(1u64 << *backoff).min(max_backoff);
		tokio::time::sleep(delay).await;
	};
	tokio::select! {
		_ = link.kick.notified() => true,
		_ = link.cancel.cancelled() => false,
		_ = timeout => true,
	}
}

async fn connect(
	core: &CoreInner,
	uri: &PeerUri,
	info: &LinkInfo,
	options: &LinkOptions,
) -> Result<LinkConnection, LinkError> {
	let protocol = core.links.protocol(&uri.scheme)?;
	let request = DialRequest {
		uri,
		sintf: &info.sintf,
		tls_sni: options.tls_sni.as_deref(),
	};
	Ok(protocol.dial(&core.links.ctx, request).await?)
}

/// Stops a link added with [`add`] and closes its connection.
pub(crate) fn remove(core: &CoreInner, uri: &PeerUri, sintf: &str) -> Result<(), LinkError> {
	let info = LinkInfo {
		uri: uri.without_query().to_string(),
		sintf: sintf.to_string(),
	};
	let links = core.links.lock();
	let link = links.get(&info).ok_or(LinkError::NotConfigured)?;
	link.cancel.cancel();
	if let Some(conn) = &link.status().conn {
		conn.stop.cancel();
	}
	Ok(())
}

/// Starts accepting links on `uri`. Local listeners (multicast) ignore `AllowedPublicKeys`.
pub(crate) async fn listen(
	core: &Arc<CoreInner>,
	uri: &PeerUri,
	sintf: &str,
	local: bool,
) -> Result<Listener, LinkError> {
	if matches!(uri.scheme.as_str(), "socks" | "sockstls") {
		return Err(LinkError::UnrecognisedSchema);
	}
	let protocol = core.links.protocol(&uri.scheme)?;
	let options = LinkOptions::common(uri)?;
	let mut listener = protocol.listen(&core.links.ctx, uri, sintf).await?;
	let addr = listener.local_addr();
	let cancel = core.cancel.child_token();
	let scheme = uri.scheme.to_ascii_uppercase();
	log::info!("{scheme} listener started on {addr}");
	let accept_core = core.clone();
	let accept_cancel = cancel.clone();
	let accept_uri = uri.clone();
	let accept_sintf = sintf.to_string();
	let accept_addr = addr.clone();
	tokio::spawn(async move {
		loop {
			let accepted = tokio::select! {
				accepted = listener.accept() => accepted,
				_ = accept_cancel.cancelled() => break,
			};
			let conn = match accepted {
				Ok(conn) => conn,
				Err(error) => {
					log::debug!("{scheme} listener on {accept_addr} failed to accept: {error}");
					break;
				}
			};
			let core = accept_core.clone();
			let uri = accept_uri.clone();
			let sintf = accept_sintf.clone();
			let options = options.clone();
			tokio::spawn(
				async move { run_inbound(&core, &uri, &sintf, &options, conn, local).await },
			);
		}
		accept_cancel.cancel();
		log::info!("{scheme} listener stopped on {accept_addr}");
	});
	Ok(Listener { addr, cancel })
}

async fn run_inbound(
	core: &Arc<CoreInner>,
	listen_uri: &PeerUri,
	sintf: &str,
	options: &LinkOptions,
	conn: LinkConnection,
	local: bool,
) {
	let mut uri = listen_uri.without_query();
	uri.host = conn.remote_addr.clone();
	let info = LinkInfo {
		uri: uri.to_string(),
		sintf: sintf.to_string(),
	};
	let link_conn = Arc::new(LinkConn::new());
	let link = {
		let mut links = core.links.lock();
		let link = links
			.get(&info)
			.cloned()
			.unwrap_or_else(|| Arc::new(Link::new(LinkType::Incoming, &core.cancel)));
		let mut status = link.status();
		if status.conn.is_some() {
			// Already connected to this peer
			return;
		}
		status.conn = Some(link_conn.clone());
		status.error = None;
		status.error_time = None;
		drop(status);
		links.insert(info.clone(), link.clone());
		link
	};
	let result = handler(
		core,
		LinkType::Incoming,
		options,
		conn,
		&link_conn,
		None,
		local,
	)
	.await;
	if let Err(error) = result {
		log::debug!("Link {} error: {error}", listen_uri.host);
	}
	link_conn.stop.cancel();
	core.links.remove_if_current(&info, &link);
}

/// Performs the link handshake, then runs the link until it closes.
async fn handler(
	core: &Arc<CoreInner>,
	link_type: LinkType,
	options: &LinkOptions,
	conn: LinkConnection,
	link_conn: &Arc<LinkConn>,
	handshake_done: Option<&AtomicBool>,
	local: bool,
) -> Result<(), LinkError> {
	let mut meta = Metadata::base();
	meta.public_key = Some(core.public);
	meta.priority = options.priority;
	let meta_bytes = meta
		.encode(&core.secret, &options.password)
		.map_err(|error| LinkError::Other(format!("failed to generate handshake: {error}")))?;
	let mut stream = Counted::new(conn.stream, link_conn.clone());
	let exchange = async {
		stream
			.write_all(&meta_bytes)
			.await
			.map_err(|error| LinkError::Other(format!("write handshake: {error}")))?;
		stream
			.flush()
			.await
			.map_err(|error| LinkError::Other(format!("write handshake: {error}")))?;
		read_metadata(&mut stream, &options.password)
			.await
			.map_err(|error| LinkError::Other(error.to_string()))
	};
	let remote = tokio::time::timeout(HANDSHAKE_TIMEOUT, exchange)
		.await
		.map_err(|_| LinkError::Other("i/o timeout".into()))??;
	if !remote.check() {
		return Err(LinkError::Other(format!(
			"remote node incompatible version (local {}.{}, remote {}.{})",
			meta.major_ver, meta.minor_ver, remote.major_ver, remote.minor_ver
		)));
	}
	let remote_key = remote.public_key.expect("checked");
	if remote_key == core.public {
		return Err(LinkError::ToSelf);
	}
	if !options.pinned_keys.is_empty() && !options.pinned_keys.contains(&remote_key) {
		return Err(LinkError::Other(
			"node public key that does not match pinned keys".into(),
		));
	}
	if !local && link_type == LinkType::Incoming && !core.is_allowed(&remote_key) {
		return Err(LinkError::Other(format!(
			"node public key {:?} is not in AllowedPublicKeys",
			hex::encode(remote_key.0)
		)));
	}
	let direction = if link_type == LinkType::Incoming {
		"inbound"
	} else {
		"outbound"
	};
	let remote_str = format!("{}@{}", addr_for_key(&remote_key), conn.remote_addr);
	let priority = remote.priority.max(options.priority);
	log::info!(
		"Connected {direction}: {remote_str}, source {}",
		conn.local_addr
	);
	if let Some(done) = handshake_done {
		done.store(true, Ordering::Relaxed);
	}
	let result = core
		.node
		.handle_conn(&remote_key, stream, priority, &link_conn.stop, |id| {
			*link_conn
				.peer
				.lock()
				.unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(id);
		})
		.await;
	match &result {
		Ok(()) | Err(ConnError::Closed) => {
			log::info!(
				"Disconnected {direction}: {remote_str}, source {}",
				conn.local_addr
			);
		}
		Err(ConnError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => {
			log::info!(
				"Disconnected {direction}: {remote_str}, source {}",
				conn.local_addr
			);
		}
		Err(error) => {
			log::info!(
				"Disconnected {direction}: {remote_str}, source {}; error: {error}",
				conn.local_addr
			);
		}
	}
	match result {
		Ok(()) | Err(ConnError::Closed) => Ok(()),
		Err(ConnError::Io(error)) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
		Err(error) => Err(LinkError::Other(error.to_string())),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_dial_options() {
		let key = "ab".repeat(32);
		let uri = PeerUri::parse(&format!(
			"tls://example.com:1234?key={key}&priority=3&password=pw&maxbackoff=30s"
		))
		.unwrap();
		let options = LinkOptions::for_dial(&uri).unwrap();
		assert!(options.pinned_keys.contains(&PublicKey([0xab; 32])));
		assert_eq!(options.priority, 3);
		assert_eq!(options.password, b"pw");
		assert_eq!(options.max_backoff, Duration::from_secs(30));
		assert_eq!(options.tls_sni.as_deref(), Some("example.com"));

		let uri = PeerUri::parse("tls://1.2.3.4:5?sni=10.0.0.1").unwrap();
		assert_eq!(LinkOptions::for_dial(&uri).unwrap().tls_sni, None);
	}

	#[test]
	fn rejects_bad_dial_options() {
		for (query, error) in [
			("priority=256", LinkError::PriorityInvalid),
			("key=zz", LinkError::PinnedKeyInvalid),
			("maxbackoff=1s", LinkError::MaxBackoffInvalid),
			("maxbackoff=forever", LinkError::MaxBackoffInvalid),
		] {
			let uri = PeerUri::parse(&format!("tcp://1.2.3.4:5?{query}")).unwrap();
			assert_eq!(LinkOptions::for_dial(&uri).unwrap_err(), error, "{query}");
		}
		let uri = PeerUri::parse(&format!("tcp://1.2.3.4:5?password={}", "x".repeat(65))).unwrap();
		assert_eq!(
			LinkOptions::for_dial(&uri).unwrap_err(),
			LinkError::PasswordInvalid
		);
	}
}
