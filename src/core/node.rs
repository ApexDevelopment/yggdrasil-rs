//! Drives petrified's sans-IO encrypted [`PacketConn`] with tokio tasks.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::sync::{Arc, Mutex, MutexGuard};

use petrified::encrypted::PacketConn;
use petrified::types::{Error, Event, PacketConn as _, PeerId, PublicKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio_util::sync::CancellationToken;

pub use yggdrasil_proto::session::{TYPE_SESSION_PROTO, TYPE_SESSION_TRAFFIC};

const READ_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub enum ConnError {
	Protocol(Error),
	Io(io::Error),
	/// The link or node was shut down locally.
	Closed,
}

impl fmt::Display for ConnError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			ConnError::Protocol(error) => error.fmt(f),
			ConnError::Io(error) => error.fmt(f),
			ConnError::Closed => f.write_str("use of closed network connection"),
		}
	}
}

impl std::error::Error for ConnError {}

struct PeerSlot {
	writer_wake: Arc<Notify>,
	closed: CancellationToken,
	/// Why the protocol dropped this peer, if it did.
	error: Option<Error>,
}

pub(crate) struct NodeState {
	pub conn: PacketConn,
	peers: HashMap<PeerId, PeerSlot>,
	/// Session traffic waiting to be read, without its type byte.
	inbox: VecDeque<(PublicKey, Vec<u8>)>,
	inbox_bytes: usize,
	max_inbox_bytes: usize,
	proto: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
}

pub(crate) struct Node {
	state: Mutex<NodeState>,
	timer_wake: Notify,
	inbox_wake: Notify,
	closed: CancellationToken,
}

impl Node {
	/// Wraps `conn` and starts its timer task. Protocol packets are sent to `proto`.
	pub fn start(
		conn: PacketConn,
		max_inbox_bytes: usize,
		proto: mpsc::UnboundedSender<(PublicKey, Vec<u8>)>,
	) -> Arc<Node> {
		let node = Arc::new(Node {
			state: Mutex::new(NodeState {
				conn,
				peers: HashMap::new(),
				inbox: VecDeque::new(),
				inbox_bytes: 0,
				max_inbox_bytes,
				proto,
			}),
			timer_wake: Notify::new(),
			inbox_wake: Notify::new(),
			closed: CancellationToken::new(),
		});
		tokio::spawn(run_timers(node.clone()));
		node
	}

	fn lock(&self) -> MutexGuard<'_, NodeState> {
		self.state
			.lock()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
	}

	/// Runs `f` on the state, then delivers whatever it produced.
	pub fn update<T>(&self, f: impl FnOnce(&mut NodeState) -> T) -> T {
		let mut state = self.lock();
		let result = f(&mut state);
		self.after_update(&mut state, true);
		result
	}

	/// Reads the state without changing it.
	pub fn inspect<T>(&self, f: impl FnOnce(&NodeState) -> T) -> T {
		f(&self.lock())
	}

	/// Acts on everything an update produced. `wake_timer` should be false
	/// only for the timer task itself.
	fn after_update(&self, state: &mut NodeState, wake_timer: bool) {
		while let Some(Event::PeerClosed { peer, error }) = state.conn.poll_event() {
			if let Some(slot) = state.peers.get_mut(&peer) {
				slot.error = Some(error);
				slot.closed.cancel();
			}
		}
		let mut received = false;
		while let Some((from, mut packet)) = state.conn.recv() {
			match packet.first() {
				Some(&TYPE_SESSION_TRAFFIC) => {
					packet.remove(0);
					state.inbox_bytes += packet.len();
					state.inbox.push_back((from, packet));
					received = true;
				}
				Some(&TYPE_SESSION_PROTO) => {
					packet.remove(0);
					let _ = state.proto.send((from, packet));
				}
				_ => {}
			}
		}
		while state.inbox_bytes > state.max_inbox_bytes {
			let Some((_, dropped)) = state.inbox.pop_front() else {
				break;
			};
			state.inbox_bytes -= dropped.len();
		}
		for (id, slot) in &state.peers {
			if !state.conn.peer_transmit(*id).is_empty() {
				slot.writer_wake.notify_one();
			}
		}
		if wake_timer {
			self.timer_wake.notify_one();
		}
		if received {
			self.inbox_wake.notify_waiters();
		}
	}

	/// Runs a peer link until it fails, `stop` is cancelled, or the node closes.
	/// `registered` is called with the link's ID once the protocol accepts it.
	pub async fn handle_conn<S>(
		self: &Arc<Self>,
		key: &PublicKey,
		stream: S,
		priority: u8,
		stop: &CancellationToken,
		registered: impl FnOnce(PeerId),
	) -> Result<(), ConnError>
	where
		S: AsyncRead + AsyncWrite + Send + 'static,
	{
		let closed = self.closed.child_token();
		let writer_wake = Arc::new(Notify::new());
		let id = self
			.update(|state| {
				let id = state.conn.handle_conn(key, priority)?;
				state.peers.insert(
					id,
					PeerSlot {
						writer_wake: writer_wake.clone(),
						closed: closed.clone(),
						error: None,
					},
				);
				Ok(id)
			})
			.map_err(ConnError::Protocol)?;
		registered(id);
		let (mut reader, writer) = tokio::io::split(stream);
		let writer_task = tokio::spawn(run_writer(
			self.clone(),
			id,
			writer,
			writer_wake,
			closed.clone(),
		));
		let mut buf = vec![0u8; READ_BUFFER_SIZE];
		let result = loop {
			let read = tokio::select! {
				read = reader.read(&mut buf) => read,
				_ = closed.cancelled() => break Err(ConnError::Closed),
				_ = stop.cancelled() => break Err(ConnError::Closed),
			};
			let n = match read {
				Ok(0) => break Err(ConnError::Io(io::ErrorKind::UnexpectedEof.into())),
				Ok(n) => n,
				Err(error) => break Err(ConnError::Io(error)),
			};
			if let Err(error) = self.update(|state| state.conn.handle_peer_data(id, &buf[..n])) {
				break Err(ConnError::Protocol(error));
			}
		};
		closed.cancel();
		let _ = writer_task.await;
		self.update(|state| {
			// Already gone if the protocol dropped it
			let _ = state.conn.remove_peer(id);
			match state.peers.remove(&id).and_then(|slot| slot.error) {
				// The node itself was closed, so the link did not fail
				Some(Error::Closed) => Err(ConnError::Closed),
				Some(error) => Err(ConnError::Protocol(error)),
				None => result,
			}
		})
	}

	pub fn write_to(&self, data: &[u8], dest: &PublicKey) -> Result<usize, Error> {
		self.update(|state| state.conn.write_to(data, dest))
	}

	/// Waits for the next session traffic packet. Returns `None` once the node is closed.
	pub async fn recv(&self) -> Option<(PublicKey, Vec<u8>)> {
		loop {
			let notified = self.inbox_wake.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			{
				let mut state = self.lock();
				if let Some((from, packet)) = state.inbox.pop_front() {
					state.inbox_bytes -= packet.len();
					return Some((from, packet));
				}
				if state.conn.is_closed() {
					return None;
				}
			}
			tokio::select! {
				_ = notified => {}
				_ = self.closed.cancelled() => {}
			}
		}
	}

	pub fn close(&self) {
		self.update(|state| {
			let _ = state.conn.close();
			for slot in state.peers.values() {
				slot.closed.cancel();
			}
		});
		self.closed.cancel();
		self.inbox_wake.notify_waiters();
	}
}

async fn run_timers(node: Arc<Node>) {
	loop {
		let deadline = {
			let mut state = node.lock();
			state.conn.handle_timeout();
			node.after_update(&mut state, false);
			state
				.conn
				.poll_timeout()
				.map(|deadline| deadline.saturating_duration_since(state.conn.now()))
		};
		let sleep = tokio::time::sleep(deadline.unwrap_or(std::time::Duration::from_secs(1)));
		tokio::select! {
			_ = sleep => {}
			_ = node.timer_wake.notified() => {}
			_ = node.closed.cancelled() => return,
		}
	}
}

async fn run_writer<W: AsyncWrite + Unpin>(
	node: Arc<Node>,
	id: PeerId,
	mut writer: W,
	wake: Arc<Notify>,
	closed: CancellationToken,
) {
	let mut buf = Vec::new();
	loop {
		buf.clear();
		node.inspect(|state| buf.extend_from_slice(state.conn.peer_transmit(id)));
		if buf.is_empty() {
			tokio::select! {
				_ = wake.notified() => continue,
				_ = closed.cancelled() => break,
			}
		}
		let written = tokio::select! {
			written = async {
				writer.write_all(&buf).await?;
				writer.flush().await
			} => written,
			_ = closed.cancelled() => break,
		};
		if written.is_err() {
			closed.cancel();
			break;
		}
		node.update(|state| state.conn.peer_consume(id, buf.len()));
	}
	let _ = writer.shutdown().await;
}
