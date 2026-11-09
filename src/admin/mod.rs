//! The admin socket: newline-delimited JSON requests over a UNIX or TCP socket,
//! with the same protocol and responses as yggdrasil-go's.

mod handlers;

use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::core::link::BoxFuture;
use crate::core::uri::PeerUri;
use crate::core::{BoxError, Core};

const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

pub type HandlerResult = Result<Value, String>;
type HandlerFn = Arc<dyn Fn(Map<String, Value>) -> BoxFuture<'static, HandlerResult> + Send + Sync>;

struct Handler {
	description: String,
	args: Vec<String>,
	call: HandlerFn,
}

pub struct AdminSocket {
	core: Core,
	handlers: RwLock<BTreeMap<String, Handler>>,
	cancel: CancellationToken,
	/// The listening address, e.g. `/var/run/yggdrasil.sock` or `127.0.0.1:9001`.
	addr: String,
}

enum AdminListener {
	Tcp(tokio::net::TcpListener),
	#[cfg(unix)]
	Unix(tokio::net::UnixListener, String),
}

impl AdminSocket {
	/// Starts the admin socket on `listen`, or returns `None` if it is `none` or empty.
	pub async fn new(
		core: Core,
		listen: &str,
		log_lookups: bool,
	) -> Result<Option<Arc<Self>>, BoxError> {
		if listen.is_empty() || listen == "none" {
			return Ok(None);
		}
		let (listener, addr) = bind(listen).await?;
		let admin = Arc::new(AdminSocket {
			core,
			handlers: RwLock::new(BTreeMap::new()),
			cancel: CancellationToken::new(),
			addr,
		});
		let network = match &listener {
			AdminListener::Tcp(_) => "TCP",
			#[cfg(unix)]
			AdminListener::Unix(..) => "UNIX",
		};
		log::info!("{network} admin socket listening on {}", admin.addr);
		admin.add_list_handler();
		if log_lookups {
			handlers::add_lookups_handler(&admin);
		}
		handlers::add_core_handlers(&admin);
		tokio::spawn(admin.clone().run(listener));
		Ok(Some(admin))
	}

	pub fn core(&self) -> &Core {
		&self.core
	}

	pub fn local_addr(&self) -> &str {
		&self.addr
	}

	/// Registers a request handler. Names are case-insensitive.
	pub fn add_handler<F, Fut>(
		&self,
		name: &str,
		description: &str,
		args: &[&str],
		handler: F,
	) -> Result<(), String>
	where
		F: Fn(Map<String, Value>) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = HandlerResult> + Send + 'static,
	{
		let mut handlers = self
			.handlers
			.write()
			.unwrap_or_else(|poisoned| poisoned.into_inner());
		let name = name.to_lowercase();
		if handlers.contains_key(&name) {
			return Err("handler already exists".into());
		}
		handlers.insert(
			name,
			Handler {
				description: description.into(),
				args: args.iter().map(|arg| arg.to_string()).collect(),
				call: Arc::new(move |args| Box::pin(handler(args))),
			},
		);
		Ok(())
	}

	/// Registers the handlers for this node's own state, like Go's `SetupAdminHandlers`.
	pub fn setup_admin_handlers(self: &Arc<Self>) {
		handlers::add_node_handlers(self);
	}

	fn add_list_handler(self: &Arc<Self>) {
		let admin = Arc::downgrade(self);
		let _ = self.add_handler("list", "List available commands", &[], move |_| {
			let admin = admin.upgrade();
			async move {
				let admin = admin.ok_or("admin socket stopped")?;
				let handlers = admin
					.handlers
					.read()
					.unwrap_or_else(|poisoned| poisoned.into_inner());
				let list: Vec<Value> = handlers
					.iter()
					.map(|(name, handler)| {
						let mut entry = Map::new();
						entry.insert("command".into(), name.clone().into());
						entry.insert("description".into(), handler.description.clone().into());
						if !handler.args.is_empty() {
							entry.insert("fields".into(), handler.args.clone().into());
						}
						Value::Object(entry)
					})
					.collect();
				Ok(Value::Object(Map::from_iter([(
					"list".to_string(),
					Value::Array(list),
				)])))
			}
		});
	}

	pub fn stop(&self) {
		self.cancel.cancel();
	}

	async fn run(self: Arc<Self>, listener: AdminListener) {
		loop {
			let accepted: io::Result<Box<dyn Connection>> = tokio::select! {
				_ = self.cancel.cancelled() => break,
				accepted = accept(&listener) => accepted,
			};
			match accepted {
				Ok(conn) => {
					tokio::spawn(self.clone().handle_connection(conn));
				}
				Err(error) => log::debug!("Admin socket accept error: {error}"),
			}
		}
		#[cfg(unix)]
		if let AdminListener::Unix(_, path) = &listener {
			let _ = std::fs::remove_file(path);
		}
	}

	async fn handle_connection(self: Arc<Self>, mut conn: Box<dyn Connection>) {
		let mut buffer = Vec::new();
		let mut total = 0;
		loop {
			let (request, keep_alive) = match read_request(&mut conn, &mut buffer, &mut total).await
			{
				Ok(request) => self.answer(&request).await,
				Err(error) => (
					error_response(
						Value::Object(Map::from_iter([("request".to_string(), Value::from(""))])),
						&error,
					),
					false,
				),
			};
			let mut out = crate::json::to_string_pretty(&request).unwrap_or_default();
			out.push('\n');
			if conn.write_all(out.as_bytes()).await.is_err() || !keep_alive {
				break;
			}
		}
		let _ = conn.shutdown().await;
	}

	/// Runs one request, returning the response and whether to keep the connection open.
	async fn answer(&self, raw: &Value) -> (Value, bool) {
		let fields = match raw {
			Value::Object(fields) => fields,
			_ => {
				let request =
					Value::Object(Map::from_iter([("request".to_string(), Value::from(""))]));
				return (
					error_response(request, "failed to unmarshal request"),
					false,
				);
			}
		};
		// Go matches field names case-insensitively
		let field = |name: &str| {
			fields
				.iter()
				.rev()
				.find(|(key, _)| key.eq_ignore_ascii_case(name))
				.map(|(_, value)| value)
		};
		let name = match field("request") {
			None | Some(Value::Null) => String::new(),
			Some(Value::String(name)) => name.clone(),
			Some(_) => {
				let request =
					Value::Object(Map::from_iter([("request".to_string(), Value::from(""))]));
				return (
					error_response(request, "failed to unmarshal request"),
					false,
				);
			}
		};
		let keep_alive = matches!(field("keepalive"), Some(Value::Bool(true)));
		let arguments = match field("arguments") {
			None | Some(Value::Null) => Value::Object(Map::new()),
			Some(arguments) => arguments.clone(),
		};
		let mut echo = Map::new();
		echo.insert("request".into(), name.clone().into());
		echo.insert("arguments".into(), arguments.clone());
		if keep_alive {
			echo.insert("keepalive".into(), true.into());
		}
		let echo = Value::Object(echo);
		if name.is_empty() {
			return (error_response(echo, "no request specified"), keep_alive);
		}
		let request_name = name.to_lowercase();
		let handler = self
			.handlers
			.read()
			.unwrap_or_else(|poisoned| poisoned.into_inner())
			.get(&request_name)
			.map(|handler| handler.call.clone());
		let Some(handler) = handler else {
			let error = format!("unknown action '{request_name}', try 'list' for help");
			return (error_response(echo, &error), keep_alive);
		};
		let Value::Object(arguments) = arguments else {
			return (
				error_response(echo, "json: cannot unmarshal into request arguments"),
				keep_alive,
			);
		};
		match handler(arguments).await {
			Ok(response) => {
				let mut out = Map::new();
				out.insert("status".into(), "success".into());
				out.insert("request".into(), echo);
				out.insert("response".into(), response);
				(Value::Object(out), keep_alive)
			}
			Err(error) => (error_response(echo, &error), keep_alive),
		}
	}
}

fn error_response(request: Value, error: &str) -> Value {
	let mut out = Map::new();
	out.insert("status".into(), "error".into());
	out.insert("error".into(), error.into());
	out.insert("request".into(), request);
	out.insert("response".into(), Value::Null);
	Value::Object(out)
}

trait Connection: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Connection for T {}

async fn accept(listener: &AdminListener) -> io::Result<Box<dyn Connection>> {
	Ok(match listener {
		AdminListener::Tcp(listener) => Box::new(listener.accept().await?.0),
		#[cfg(unix)]
		AdminListener::Unix(listener, _) => Box::new(listener.accept().await?.0),
	})
}

/// Reads the next JSON value from the connection, keeping any extra bytes for the next call.
async fn read_request(
	conn: &mut Box<dyn Connection>,
	buffer: &mut Vec<u8>,
	total: &mut usize,
) -> Result<Value, String> {
	let read = async {
		loop {
			let mut values = serde_json::Deserializer::from_slice(buffer).into_iter::<Value>();
			match values.next() {
				Some(Ok(value)) => {
					let consumed = values.byte_offset();
					buffer.drain(..consumed);
					return Ok(value);
				}
				Some(Err(error)) if !error.is_eof() => {
					return Err(format!("failed to decode request: {error}"));
				}
				_ => {}
			}
			let mut chunk = [0u8; 4096];
			let n = conn
				.read(&mut chunk)
				.await
				.map_err(|error| format!("failed to decode request: {error}"))?;
			*total += n;
			if n == 0 || *total > MAX_REQUEST_SIZE {
				return Err("failed to decode request: EOF".into());
			}
			buffer.extend_from_slice(&chunk[..n]);
		}
	};
	tokio::time::timeout(READ_TIMEOUT, read)
		.await
		.map_err(|_| "failed to decode request: i/o timeout".to_string())?
}

async fn bind(listen: &str) -> Result<(AdminListener, String), BoxError> {
	let uri = PeerUri::parse(listen).ok();
	match uri.as_ref().map(|uri| uri.scheme.as_str()) {
		#[cfg(unix)]
		Some("unix") => {
			let path = uri.expect("parsed").path;
			bind_unix(&path).await
		}
		Some("tcp") => {
			let host = uri.expect("parsed").host;
			let listener = tokio::net::TcpListener::bind(&host).await?;
			let addr = listener.local_addr()?.to_string();
			Ok((AdminListener::Tcp(listener), addr))
		}
		_ => {
			let listener = tokio::net::TcpListener::bind(listen).await?;
			let addr = listener.local_addr()?.to_string();
			Ok((AdminListener::Tcp(listener), addr))
		}
	}
}

#[cfg(unix)]
async fn bind_unix(path: &str) -> Result<(AdminListener, String), BoxError> {
	use std::os::unix::fs::PermissionsExt;

	if std::fs::metadata(path).is_ok() {
		log::debug!("Admin socket {path} already exists, trying to clean up");
		let in_use = matches!(
			tokio::time::timeout(
				Duration::from_secs(2),
				tokio::net::UnixStream::connect(path)
			)
			.await,
			Ok(Ok(_)) | Err(_)
		);
		if in_use {
			return Err(format!(
				"Admin socket {path} already exists and is in use by another process"
			)
			.into());
		}
		std::fs::remove_file(path)
			.map_err(|error| format!("{path} already exists and was not cleaned up: {error}"))?;
		log::debug!("{path} was cleaned up");
	}
	let listener = tokio::net::UnixListener::bind(path)?;
	if !path.starts_with('@')
		&& std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).is_err()
	{
		log::warn!("WARNING: {path} may have unsafe permissions!");
	}
	Ok((
		AdminListener::Unix(listener, path.to_string()),
		path.to_string(),
	))
}

/// Reads a string argument, matching its name case-insensitively as Go does.
pub fn string_arg(args: &Map<String, Value>, name: &str) -> Result<String, String> {
	match args
		.iter()
		.rev()
		.find(|(key, _)| key.eq_ignore_ascii_case(name))
	{
		None | Some((_, Value::Null)) => Ok(String::new()),
		Some((_, Value::String(value))) => Ok(value.clone()),
		Some((key, _)) => Err(format!(
			"json: cannot unmarshal into Go struct field .{key} of type string"
		)),
	}
}
