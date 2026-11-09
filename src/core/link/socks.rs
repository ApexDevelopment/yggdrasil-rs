use std::io;

use tokio_socks::tcp::Socks5Stream;

use super::{
	BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol, first_success,
	tcp, tls,
};
use crate::core::uri::PeerUri;

/// Dials through a SOCKS5 proxy: `socks://proxy:port/target:port`, optionally
/// with `user:password@` and, for `sockstls`, TLS to the target.
pub struct Socks {
	pub tls: bool,
}

impl LinkProtocol for Socks {
	fn dial<'a>(
		&'a self,
		ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let uri = request.uri;
			let target = uri
				.path
				.trim_matches('/')
				.split('/')
				.next()
				.unwrap_or_default()
				.to_string();
			let credentials = uri
				.user
				.as_ref()
				.filter(|(name, _)| !name.is_empty())
				.map(|(name, password)| (name.clone(), password.clone().unwrap_or_default()));
			let (hostname, addrs) = ctx.suitable_addresses(uri, request.sintf).await?;
			first_success(addrs, |addr| {
				let target = target.as_str();
				let credentials = &credentials;
				let hostname = &hostname;
				async move {
					let (proxy, local_addr, remote_addr) =
						tcp::connection(tcp::connect(addr, request.sintf).await?)?;
					let stream = match credentials {
						Some((name, password)) => {
							Socks5Stream::connect_with_password_and_socket(
								proxy, target, name, password,
							)
							.await
						}
						None => Socks5Stream::connect_with_socket(proxy, target).await,
					}
					.map_err(io::Error::other)?;
					let stream: Box<dyn super::LinkStream> = if self.tls {
						Box::new(
							tls::client_handshake(ctx, stream, hostname, request.tls_sni).await?,
						)
					} else {
						Box::new(stream)
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
		_uri: &'a PeerUri,
		_sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async { Err(io::Error::other("SOCKS listener not supported")) })
	}
}
