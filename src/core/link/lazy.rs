use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxFuture;

/// A stream that finishes setting itself up (e.g. a TLS handshake) on first use,
/// so that slow peers never hold up a listener's accept loop.
pub enum Lazy<S> {
	Pending(BoxFuture<'static, io::Result<S>>),
	Ready(S),
	Failed,
}

impl<S> Lazy<S> {
	pub fn new(setup: impl Future<Output = io::Result<S>> + Send + 'static) -> Self {
		Lazy::Pending(Box::pin(setup))
	}
}

impl<S: Unpin> Lazy<S> {
	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut S>> {
		if let Lazy::Pending(setup) = self {
			match ready!(setup.as_mut().poll(cx)) {
				Ok(stream) => *self = Lazy::Ready(stream),
				Err(error) => {
					*self = Lazy::Failed;
					return Poll::Ready(Err(error));
				}
			}
		}
		match self {
			Lazy::Ready(stream) => Poll::Ready(Ok(stream)),
			_ => Poll::Ready(Err(io::Error::new(
				io::ErrorKind::NotConnected,
				"connection setup failed",
			))),
		}
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Lazy<S> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let stream = ready!(self.get_mut().poll_ready(cx))?;
		Pin::new(stream).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Lazy<S> {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let stream = ready!(self.get_mut().poll_ready(cx))?;
		Pin::new(stream).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let stream = ready!(self.get_mut().poll_ready(cx))?;
		Pin::new(stream).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		match self.get_mut() {
			Lazy::Ready(stream) => Pin::new(stream).poll_shutdown(cx),
			_ => Poll::Ready(Ok(())),
		}
	}
}
