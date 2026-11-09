use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::{HeaderValue, StatusCode, header};
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use super::lazy::Lazy;
use super::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol, first_success,
	tcp, tls,
};
use crate::core::uri::{PeerUri, join_host_port};

const SUBPROTOCOL: &str = "ygg-ws";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Links over WebSockets (`ws://`, or `wss://` with TLS), carrying the link's
/// byte stream in binary messages with the `ygg-ws` subprotocol.
pub struct WebSocket {
	pub secure: bool,
}

impl LinkProtocol for WebSocket {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let uri = request.uri;
			let (hostname, addrs) = ctx.suitable_addresses(uri, request.sintf).await?;
			first_success(addrs, |addr| {
				let hostname = &hostname;
				async move {
					let mut target = uri.clone();
					target.host = join_host_port(&addr.ip().to_string(), addr.port());
					let (stream, local_addr, remote_addr) =
						tcp::connection(tcp::connect(addr, request.sintf).await?)?;
					let stream: Box<dyn super::LinkStream> = if self.secure {
						let stream =
							tls::client_handshake(ctx, stream, hostname, request.tls_sni).await?;
						Box::new(client_handshake(stream, &target, hostname).await?)
					} else {
						Box::new(client_handshake(stream, &target, hostname).await?)
					};
					Ok(LinkConnection {
						stream,
						local_addr,
						remote_addr,
					})
				}
			})
			.await
		})
	}

	fn listen<'a>(
		&'a self,
		_ctx: &'a LinkContext,
		uri: &'a PeerUri,
		sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async move {
			if self.secure {
				return Err(io::Error::other(
					"WSS listener not supported, use WS listener behind reverse proxy instead",
				));
			}
			let listener = TcpListener::bind(tcp::listen_addr(uri, sintf)?).await?;
			let origins = uri.query_values("origin").map(str::to_string).collect();
			Ok(Box::new(WsListener { listener, origins }) as Box<dyn LinkListener>)
		})
	}
}

async fn client_handshake<S>(stream: S, target: &PeerUri, hostname: &str) -> io::Result<WsStream<S>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut request = target
		.to_string()
		.into_client_request()
		.map_err(io::Error::other)?;
	let headers = request.headers_mut();
	headers.insert(
		header::HOST,
		HeaderValue::from_str(hostname).map_err(io::Error::other)?,
	);
	headers.insert(
		header::SEC_WEBSOCKET_PROTOCOL,
		HeaderValue::from_static(SUBPROTOCOL),
	);
	let (stream, _) = tokio_tungstenite::client_async(request, stream)
		.await
		.map_err(io::Error::other)?;
	Ok(WsStream::new(stream))
}

struct WsListener {
	listener: TcpListener,
	/// Allowed `Origin` hosts, as glob patterns. `*` allows any.
	origins: Vec<String>,
}

impl LinkListener for WsListener {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>> {
		Box::pin(async move {
			let mut conn = LinkListener::accept(&mut self.listener).await?;
			let origins = self.origins.clone();
			let stream = conn.stream;
			conn.stream = Box::new(Lazy::new(async move {
				let handshake =
					tokio_tungstenite::accept_hdr_async(stream, |request: &Request, response| {
						check_request(request, response, &origins)
					});
				let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
					.await
					.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))?
					.map_err(io::Error::other)?;
				Ok(WsStream::new(stream))
			}));
			Ok(conn)
		})
	}

	fn local_addr(&self) -> String {
		LinkListener::local_addr(&self.listener)
	}
}

fn error_response(status: StatusCode, body: &str) -> ErrorResponse {
	let mut response = ErrorResponse::new(Some(body.to_string()));
	*response.status_mut() = status;
	response
}

/// Answers health checks, and accepts only `ygg-ws` clients from allowed origins.
fn check_request(
	request: &Request,
	mut response: Response,
	origins: &[String],
) -> Result<Response, ErrorResponse> {
	if matches!(request.uri().path(), "/health" | "/healthz") {
		return Err(error_response(StatusCode::OK, "OK"));
	}
	check_origin(request, origins)?;
	let offers_subprotocol = request
		.headers()
		.get_all(header::SEC_WEBSOCKET_PROTOCOL)
		.iter()
		.filter_map(|value| value.to_str().ok())
		.flat_map(|value| value.split(','))
		.any(|protocol| protocol.trim() == SUBPROTOCOL);
	if !offers_subprotocol {
		return Err(error_response(
			StatusCode::BAD_REQUEST,
			"client must speak the ygg-ws subprotocol",
		));
	}
	response.headers_mut().insert(
		header::SEC_WEBSOCKET_PROTOCOL,
		HeaderValue::from_static(SUBPROTOCOL),
	);
	Ok(response)
}

/// Browsers send an `Origin`, which must match the host or an allowed pattern.
fn check_origin(request: &Request, origins: &[String]) -> Result<(), ErrorResponse> {
	let Some(origin) = request.headers().get(header::ORIGIN) else {
		return Ok(());
	};
	if origins.iter().any(|pattern| pattern == "*") {
		return Ok(());
	}
	let origin = origin.to_str().unwrap_or_default();
	let origin_host = origin
		.split_once("://")
		.map(|(_, rest)| rest.split('/').next().unwrap_or_default())
		.filter(|host| !host.is_empty())
		.ok_or_else(|| {
			error_response(
				StatusCode::FORBIDDEN,
				&format!("request Origin {origin:?} is not a valid URL with a host"),
			)
		})?;
	let request_host = request
		.headers()
		.get(header::HOST)
		.and_then(|host| host.to_str().ok())
		.unwrap_or_default();
	let origin_host = origin_host.to_ascii_lowercase();
	let allowed = origin_host == request_host.to_ascii_lowercase()
		|| origins
			.iter()
			.filter(|pattern| !pattern.is_empty())
			.any(|pattern| glob_match(&pattern.to_ascii_lowercase(), &origin_host));
	if allowed {
		Ok(())
	} else {
		Err(error_response(
			StatusCode::FORBIDDEN,
			&format!("request Origin {origin:?} is not authorized for Host {request_host:?}"),
		))
	}
}

/// Matches `*` (any run of characters except `/`) and `?` (any one character).
fn glob_match(pattern: &str, text: &str) -> bool {
	let pattern: Vec<char> = pattern.chars().collect();
	let text: Vec<char> = text.chars().collect();
	fn matches(pattern: &[char], text: &[char]) -> bool {
		match pattern.split_first() {
			None => text.is_empty(),
			Some(('*', rest)) => (0..=text.len())
				.take_while(|&skip| !text[..skip].contains(&'/'))
				.any(|skip| matches(rest, &text[skip..])),
			Some(('?', rest)) => !text.is_empty() && text[0] != '/' && matches(rest, &text[1..]),
			Some((c, rest)) => text.first() == Some(c) && matches(rest, &text[1..]),
		}
	}
	matches(&pattern, &text)
}

/// A WebSocket viewed as a byte stream: each write is one binary message.
struct WsStream<S> {
	inner: WebSocketStream<S>,
	pending: Vec<u8>,
	offset: usize,
}

impl<S> WsStream<S> {
	fn new(inner: WebSocketStream<S>) -> Self {
		WsStream {
			inner,
			pending: Vec::new(),
			offset: 0,
		}
	}
}

fn to_io(error: WsError) -> io::Error {
	match error {
		WsError::ConnectionClosed | WsError::AlreadyClosed => io::ErrorKind::UnexpectedEof.into(),
		WsError::Io(error) => error,
		other => io::Error::other(other),
	}
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		loop {
			if self.offset < self.pending.len() {
				let n = buf.remaining().min(self.pending.len() - self.offset);
				let start = self.offset;
				buf.put_slice(&self.pending[start..start + n]);
				self.offset += n;
				return Poll::Ready(Ok(()));
			}
			match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
				Some(Ok(Message::Binary(data))) => {
					self.pending = data.to_vec();
					self.offset = 0;
				}
				Some(Ok(Message::Text(_))) => {
					return Poll::Ready(Err(io::Error::new(
						io::ErrorKind::InvalidData,
						"unexpected text message",
					)));
				}
				Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
				Some(Ok(_)) => {}
				Some(Err(error)) => return Poll::Ready(Err(to_io(error))),
			}
		}
	}
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(to_io)?;
		Pin::new(&mut self.inner)
			.start_send(Message::binary(buf.to_vec()))
			.map_err(to_io)?;
		Poll::Ready(Ok(buf.len()))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_flush(cx).map_err(to_io)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_close(cx).map_err(to_io)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn globs_match_like_go_path_match() {
		assert!(glob_match("*.example.com", "a.example.com"));
		assert!(glob_match("example.com:*", "example.com:8080"));
		assert!(glob_match("h?st", "host"));
		assert!(!glob_match("*.example.com", "example.com"));
		assert!(!glob_match("*", "a/b"));
	}
}
