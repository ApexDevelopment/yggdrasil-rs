//! The metadata exchanged at the start of every peer link.

use tokio::io::{AsyncRead, AsyncReadExt};
pub use yggdrasil_proto::handshake::*;

/// Reads and verifies metadata from the start of a stream.
pub async fn read_metadata<R: AsyncRead + Unpin>(
	reader: &mut R,
	password: &[u8],
) -> Result<Metadata, HandshakeError> {
	let io_error = |error: std::io::Error| HandshakeError::Io(error.to_string());
	let mut header = [0u8; HEADER_LEN];
	reader.read_exact(&mut header).await.map_err(io_error)?;
	let mut body = vec![0u8; Metadata::body_length(&header)?];
	reader.read_exact(&mut body).await.map_err(io_error)?;
	Metadata::decode_body(&body, password)
}
