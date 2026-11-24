//! Length-prefixed JSON frames: a `u32` big-endian length, then the JSON bytes.

use serde::Serialize;
use serde::de::DeserializeOwned;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum size of one frame body: 1 MiB.
pub const MAX_FRAME: usize = 1024 * 1024;

/// Error of frame reading or writing.
#[derive(Debug)]
pub enum FrameError {
    /// The peer closed the stream between two frames.
    Closed,
    /// The frame is larger than [`MAX_FRAME`].
    TooLarge(usize),
    /// The body is not valid JSON of the expected type.
    Json(serde_json::Error),
    /// An I/O failure.
    Io(io::Error),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "connection closed"),
            Self::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the {MAX_FRAME} byte limit"),
            Self::Json(e) => write!(f, "invalid frame body: {e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<FrameError> for warden_core::WardenError {
    fn from(e: FrameError) -> Self {
        warden_core::WardenError::Ipc(e.to_string())
    }
}

/// Write `value` as one frame. Refuses a body above [`MAX_FRAME`] before it writes anything.
pub async fn write_msg<W, T>(w: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let body = serde_json::to_vec(value).map_err(FrameError::Json)?;
    if body.len() > MAX_FRAME {
        return Err(FrameError::TooLarge(body.len()));
    }
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf).await.map_err(FrameError::Io)?;
    w.flush().await.map_err(FrameError::Io)
}

/// Read one frame and parse it. Checks the length before it allocates the body.
pub async fn read_msg<R, T>(r: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut head = [0u8; 4];
    match r.read_exact(&mut head).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(e) => return Err(FrameError::Io(e)),
    }
    let len = u32::from_be_bytes(head) as usize;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await.map_err(FrameError::Io)?;
    serde_json::from_slice(&body).map_err(FrameError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(64 * 1024);
        write_msg(&mut a, &serde_json::json!({"x": 1}))
            .await
            .unwrap();
        let v: serde_json::Value = read_msg(&mut b).await.unwrap();
        assert_eq!(v["x"], 1);

        let big = "a".repeat(MAX_FRAME + 1);
        assert!(matches!(
            write_msg(&mut a, &big).await,
            Err(FrameError::TooLarge(_))
        ));

        a.write_all(&((MAX_FRAME as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let r: Result<serde_json::Value, _> = read_msg(&mut b).await;
        assert!(matches!(r, Err(FrameError::TooLarge(_))));

        drop(a);
        let r: Result<serde_json::Value, _> = read_msg(&mut b).await;
        assert!(matches!(r, Err(FrameError::Closed)));
    }
}
