use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, Join, ReadBuf};

use super::lazy::Lazy;
use super::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol, first_success,
	format_socket_addr, tcp, tls,
};
use crate::core::uri::PeerUri;

const STREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Links over a single bidirectional QUIC stream.
pub struct Quic;

fn transport_config() -> Arc<TransportConfig> {
	let mut transport = TransportConfig::default();
	transport
		.max_idle_timeout(Some(
			Duration::from_secs(60)
				.try_into()
				.expect("valid idle timeout"),
		))
		.keep_alive_interval(Some(Duration::from_secs(20)))
		.max_concurrent_bidi_streams(VarInt::from_u32(1))
		.max_concurrent_uni_streams(VarInt::from_u32(0));
	Arc::new(transport)
}

fn client_config(ctx: &LinkContext) -> io::Result<quinn::ClientConfig> {
	let crypto =
		QuicClientConfig::try_from(ctx.tls.quic_client.clone()).map_err(io::Error::other)?;
	let mut config = quinn::ClientConfig::new(Arc::new(crypto));
	config.transport_config(transport_config());
	Ok(config)
}

async fn dial_addr(
	ctx: &LinkContext,
	addr: SocketAddr,
	hostname: &str,
	sni: Option<&str>,
) -> io::Result<LinkConnection> {
	let bind: SocketAddr = match addr {
		SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
		SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
	};
	let endpoint = Endpoint::client(bind)?;
	let server_name = match tls::server_name(hostname, sni)? {
		rustls::pki_types::ServerName::DnsName(name) => name.as_ref().to_string(),
		rustls::pki_types::ServerName::IpAddress(ip) => std::net::IpAddr::from(ip).to_string(),
		_ => hostname.to_string(),
	};
	let connection = endpoint
		.connect_with(client_config(ctx)?, addr, &server_name)
		.map_err(io::Error::other)?
		.await
		.map_err(io::Error::other)?;
	let (send, recv) = connection.open_bi().await.map_err(io::Error::other)?;
	Ok(LinkConnection {
		local_addr: format_socket_addr(&endpoint.local_addr()?),
		remote_addr: format_socket_addr(&addr),
		stream: Box::new(QuicStream {
			io: tokio::io::join(recv, send),
			connection,
			_endpoint: Some(endpoint),
		}),
	})
}

impl LinkProtocol for Quic {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let (hostname, addrs) = ctx.suitable_addresses(request.uri, request.sintf).await?;
			first_success(addrs, |addr| {
				dial_addr(ctx, addr, &hostname, request.tls_sni)
			})
			.await
		})
	}

	fn listen<'a>(
		&'a self,
		ctx: &'a LinkContext,
		uri: &'a PeerUri,
		_sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async move {
			let crypto =
				QuicServerConfig::try_from(ctx.tls.server.clone()).map_err(io::Error::other)?;
			let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
			config.transport_config(transport_config());
			let endpoint = Endpoint::server(config, tcp::listen_addr(uri, "")?)?;
			Ok(Box::new(QuicListener { endpoint }) as Box<dyn LinkListener>)
		})
	}
}

struct QuicListener {
	endpoint: Endpoint,
}

impl Drop for QuicListener {
	fn drop(&mut self) {
		self.endpoint.close(VarInt::from_u32(0), b"");
	}
}

impl LinkListener for QuicListener {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>> {
		Box::pin(async move {
			let incoming =
				self.endpoint.accept().await.ok_or_else(|| {
					io::Error::new(io::ErrorKind::NotConnected, "listener closed")
				})?;
			let remote_addr = format_socket_addr(&incoming.remote_address());
			let stream = Lazy::new(async move {
				let connection = incoming.await.map_err(io::Error::other)?;
				let streams = tokio::time::timeout(STREAM_TIMEOUT, connection.accept_bi()).await;
				let (send, recv) = match streams {
					Ok(Ok(streams)) => streams,
					Ok(Err(error)) => {
						connection.close(
							VarInt::from_u32(1),
							format!("stream error: {error}").as_bytes(),
						);
						return Err(io::Error::other(error));
					}
					Err(_) => {
						connection.close(VarInt::from_u32(1), b"stream not created");
						return Err(io::Error::new(
							io::ErrorKind::TimedOut,
							"stream not created",
						));
					}
				};
				Ok(QuicStream {
					io: tokio::io::join(recv, send),
					connection,
					_endpoint: None,
				})
			});
			Ok(LinkConnection {
				stream: Box::new(stream),
				local_addr: LinkListener::local_addr(self),
				remote_addr,
			})
		})
	}

	fn local_addr(&self) -> String {
		self.endpoint
			.local_addr()
			.map(|addr| format_socket_addr(&addr))
			.unwrap_or_default()
	}
}

/// One stream of a QUIC connection, which closes the connection when dropped.
struct QuicStream {
	io: Join<RecvStream, SendStream>,
	connection: Connection,
	/// Outbound connections own their endpoint.
	_endpoint: Option<Endpoint>,
}

impl Drop for QuicStream {
	fn drop(&mut self) {
		self.connection.close(VarInt::from_u32(0), b"");
	}
}

impl AsyncRead for QuicStream {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_read(cx, buf)
	}
}

impl AsyncWrite for QuicStream {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		Pin::new(&mut self.io).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_shutdown(cx)
	}
}
