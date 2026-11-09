use std::io;
use std::time::Duration;

use tokio::net::{UnixListener, UnixStream};

use super::{BoxFuture, DialRequest, LinkConnection, LinkContext, LinkListener, LinkProtocol};
use crate::core::uri::PeerUri;

const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Unix;

impl LinkProtocol for Unix {
	fn dial<'a>(
		&'a self,
		_ctx: &'a LinkContext,
		request: DialRequest<'a>,
	) -> BoxFuture<'a, io::Result<LinkConnection>> {
		Box::pin(async move {
			let path = request.uri.path.clone();
			let stream = tokio::time::timeout(DIAL_TIMEOUT, UnixStream::connect(&path))
				.await
				.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "i/o timeout"))??;
			Ok(LinkConnection {
				stream: Box::new(stream),
				local_addr: String::new(),
				remote_addr: path,
			})
		})
	}

	fn listen<'a>(
		&'a self,
		_ctx: &'a LinkContext,
		uri: &'a PeerUri,
		_sintf: &'a str,
	) -> BoxFuture<'a, io::Result<Box<dyn LinkListener>>> {
		Box::pin(async move {
			let listener = UnixListener::bind(&uri.path)?;
			Ok(Box::new(UnixLinkListener {
				listener,
				path: uri.path.clone(),
			}) as Box<dyn LinkListener>)
		})
	}
}

/// Removes its socket file when dropped, as Go does when a listener closes.
struct UnixLinkListener {
	listener: UnixListener,
	path: String,
}

impl Drop for UnixLinkListener {
	fn drop(&mut self) {
		let _ = std::fs::remove_file(&self.path);
	}
}

impl LinkListener for UnixLinkListener {
	fn accept(&mut self) -> BoxFuture<'_, io::Result<LinkConnection>> {
		Box::pin(async move {
			let (stream, _) = self.listener.accept().await?;
			Ok(LinkConnection {
				stream: Box::new(stream),
				local_addr: self.path.clone(),
				// Go reports unnamed peers as "@"
				remote_addr: "@".into(),
			})
		})
	}

	fn local_addr(&self) -> String {
		self.path.clone()
	}
}
