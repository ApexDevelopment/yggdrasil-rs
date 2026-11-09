use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpSocket, TcpStream};

use super::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol, first_success,
	format_socket_addr, parse_socket_addr,
};
use crate::core::uri::{PeerUri, split_host_port};

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Tcp;

/// Connects to `addr`, binding to the source interface `sintf` where the platform supports it.
pub async fn connect(addr: SocketAddr, sintf: &str) -> io::Result<TcpStream> {
	let socket = match addr {
		SocketAddr::V4(_) => TcpSocket::new_v4()?,
		SocketAddr::V6(_) => TcpSocket::new_v6()?,
	};
	#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
	if !sintf.is_empty()
		&& let Err(error) = socket.bind_device(Some(sintf.as_bytes()))
	{
		log::debug!("Failed to set SO_BINDTODEVICE: {sintf}: {error}");
	}
	#[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
	let _ = sintf;
	let stream = tokio::time::timeout(DIAL_TIMEOUT, socket.connect(addr))
		.await
		.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))??;
	stream.set_nodelay(true)?;
	Ok(stream)
}

pub fn connection(stream: TcpStream) -> io::Result<(TcpStream, String, String)> {
	let local = format_socket_addr(&stream.local_addr()?);
	let remote = format_socket_addr(&stream.peer_addr()?);
	Ok((stream, local, remote))
}

/// The address to listen on, with `sintf` as the zone if one is given.
pub fn listen_addr(uri: &PeerUri, sintf: &str) -> io::Result<SocketAddr> {
	let mut hostport = uri.host.clone();
	if !sintf.is_empty()
		&& let Ok((host, port)) = split_host_port(&hostport)
	{
		hostport = format!("[{host}%{sintf}]:{port}");
	}
	parse_socket_addr(&hostport)
}

impl LinkProtocol for Tcp {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let (_, addrs) = ctx.suitable_addresses(request.uri, request.sintf).await?;
			let stream = first_success(addrs, |addr| connect(addr, request.sintf)).await?;
			let (stream, local_addr, remote_addr) = connection(stream)?;
			Ok(LinkConnection {
				stream: Box::new(stream),
				local_addr,
				remote_addr,
			})
		})
	}

	fn listen<'a>(
		&'a self,
		_ctx: &'a LinkContext,
		uri: &'a PeerUri,
		sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async move {
			let listener = TcpListener::bind(listen_addr(uri, sintf)?).await?;
			Ok(Box::new(listener) as Box<dyn LinkListener>)
		})
	}
}

impl LinkListener for TcpListener {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>> {
		Box::pin(async move {
			let (stream, _) = TcpListener::accept(self).await?;
			stream.set_nodelay(true)?;
			let (stream, local_addr, remote_addr) = connection(stream)?;
			Ok(LinkConnection {
				stream: Box::new(stream),
				local_addr,
				remote_addr,
			})
		})
	}

	fn local_addr(&self) -> String {
		TcpListener::local_addr(self)
			.map(|addr| format_socket_addr(&addr))
			.unwrap_or_default()
	}
}
