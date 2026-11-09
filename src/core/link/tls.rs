use std::io;
use std::net::IpAddr;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, TlsConnector};

use super::lazy::Lazy;
use super::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol, first_success,
	tcp,
};
use crate::core::uri::PeerUri;

pub struct Tls;

/// The name to verify (and send as SNI): the configured SNI, else the dialed hostname.
pub fn server_name(hostname: &str, sni: Option<&str>) -> io::Result<ServerName<'static>> {
	let name = sni.unwrap_or(hostname);
	let name = name.split('%').next().unwrap_or(name);
	if let Ok(ip) = name.parse::<IpAddr>() {
		return Ok(ServerName::IpAddress(ip.into()));
	}
	ServerName::try_from(name.to_string()).map_err(io::Error::other)
}

/// Runs a TLS client handshake over `stream`.
pub async fn client_handshake<S>(
	ctx: &LinkContext,
	stream: S,
	hostname: &str,
	sni: Option<&str>,
) -> io::Result<tokio_rustls::client::TlsStream<S>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let connector = TlsConnector::from(ctx.tls.client.clone());
	connector.connect(server_name(hostname, sni)?, stream).await
}

impl LinkProtocol for Tls {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let (hostname, addrs) = ctx.suitable_addresses(request.uri, request.sintf).await?;
			first_success(addrs, |addr| {
				let hostname = &hostname;
				async move {
					let (stream, local_addr, remote_addr) =
						tcp::connection(tcp::connect(addr, request.sintf).await?)?;
					let stream = client_handshake(ctx, stream, hostname, request.tls_sni).await?;
					Ok(LinkConnection {
						stream: Box::new(stream),
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
		ctx: &'a LinkContext,
		uri: &'a PeerUri,
		sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async move {
			let listener = TcpListener::bind(tcp::listen_addr(uri, sintf)?).await?;
			Ok(Box::new(TlsListener {
				listener,
				acceptor: TlsAcceptor::from(ctx.tls.server.clone()),
			}) as Box<dyn LinkListener>)
		})
	}
}

struct TlsListener {
	listener: TcpListener,
	acceptor: TlsAcceptor,
}

impl LinkListener for TlsListener {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>> {
		Box::pin(async move {
			let mut conn = LinkListener::accept(&mut self.listener).await?;
			let acceptor = self.acceptor.clone();
			let stream = conn.stream;
			conn.stream = Box::new(Lazy::new(async move { acceptor.accept(stream).await }));
			Ok(conn)
		})
	}

	fn local_addr(&self) -> String {
		LinkListener::local_addr(&self.listener)
	}
}
