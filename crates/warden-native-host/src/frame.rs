//! Chrome native messaging framing.

use crate::HostError;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest message in each direction: 1 MiB.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Read one message. Return `None` at a clean end of input.
///
/// A length above [`MAX_MESSAGE`] fails before the host reads the body.
pub async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>, HostError> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < 4 {
        let n = r.read(&mut len[got..]).await?;
        if n == 0 {
            if got == 0 {
                return Ok(None);
            }
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
        }
        got += n;
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(HostError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Write one JSON message. A body above [`MAX_MESSAGE`] becomes an error message.
pub async fn write_message<W: AsyncWrite + Unpin>(
    w: &mut W,
    value: &Value,
) -> Result<(), HostError> {
    let mut body = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    if body.len() > MAX_MESSAGE {
        body =
            br#"{"type":"error","code":"too_large","message":"response exceeds the 1 MiB limit"}"#
                .to_vec();
    }
    let len = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}
