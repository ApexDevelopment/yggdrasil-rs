use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{LinkConn, LinkStream};

/// Counts the bytes read from and written to a link's stream.
pub struct Counted {
	inner: Box<dyn LinkStream>,
	stats: Arc<LinkConn>,
}

impl Counted {
	pub(crate) fn new(inner: Box<dyn LinkStream>, stats: Arc<LinkConn>) -> Self {
		Counted { inner, stats }
	}
}

impl AsyncRead for Counted {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let before = buf.filled().len();
		let result = Pin::new(&mut self.inner).poll_read(cx, buf);
		let read = (buf.filled().len() - before) as u64;
		self.stats.rx.fetch_add(read, Ordering::Relaxed);
		result
	}
}

impl AsyncWrite for Counted {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let result = Pin::new(&mut self.inner).poll_write(cx, buf);
		if let Poll::Ready(Ok(written)) = &result {
			self.stats.tx.fetch_add(*written as u64, Ordering::Relaxed);
		}
		result
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Pin::new(&mut self.inner).poll_shutdown(cx)
	}
}
