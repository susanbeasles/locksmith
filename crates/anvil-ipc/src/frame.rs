use std::io::ErrorKind;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::IpcError;

/// 4-byte ASCII magic prefix (`"LKSM"`) for all Locksmith IPC frames.
pub const FRAME_MAGIC: [u8; 4] = *b"LKSM";
/// Normative binary framing version.
pub const FRAME_VERSION_V1: u8 = 1;
/// Exact byte length of a binary frame header (`4 + 1 + 1 + 4 = 10` bytes).
pub const FRAME_HEADER_LEN: usize = 10;
/// Hard pre-allocation cap on IPC frame payloads (`64 KiB`).
pub const MAX_FRAME_BYTES: usize = 65_536;

/// Wire message discriminator byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    CommandRequest = 0x01,
    CommandResponse = 0x02,
    EgressProxyFrame = 0x03,
    Heartbeat = 0x04,
    ErrorResponse = 0xFF,
}

impl TryFrom<u8> for MessageType {
    type Error = IpcError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::CommandRequest),
            0x02 => Ok(Self::CommandResponse),
            0x03 => Ok(Self::EgressProxyFrame),
            0x04 => Ok(Self::Heartbeat),
            0xFF => Ok(Self::ErrorResponse),
            other => Err(IpcError::UnknownMessageType(other)),
        }
    }
}

/// Decoded bounded Locksmith IPC frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrame {
    pub msg_type: MessageType,
    pub payload: Vec<u8>,
}

impl WireFrame {
    /// Serializes this frame into `[magic || version || msg_type || len_be || payload]`.
    pub fn encode(&self) -> Result<Vec<u8>, IpcError> {
        if self.payload.len() > MAX_FRAME_BYTES {
            let declared_len = u32::try_from(self.payload.len()).unwrap_or(u32::MAX);
            return Err(IpcError::FrameTooLarge {
                declared_len,
                max_len: MAX_FRAME_BYTES,
            });
        }
        let len_u32 = u32::try_from(self.payload.len()).map_err(|_| IpcError::FrameTooLarge {
            declared_len: u32::MAX,
            max_len: MAX_FRAME_BYTES,
        })?;

        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&FRAME_MAGIC);
        out.push(FRAME_VERSION_V1);
        out.push(self.msg_type as u8);
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }
}

fn map_read_error(err: std::io::Error) -> IpcError {
    if err.kind() == ErrorKind::UnexpectedEof {
        IpcError::UnexpectedEof
    } else {
        IpcError::IoError(err.to_string())
    }
}

/// Validates a 10-byte stack header and enforces `MAX_FRAME_BYTES` **before**
/// any payload buffer is allocated.
pub fn parse_frame_header(
    header: &[u8; FRAME_HEADER_LEN],
) -> Result<(MessageType, usize), IpcError> {
    let magic = [header[0], header[1], header[2], header[3]];
    if magic != FRAME_MAGIC {
        return Err(IpcError::InvalidMagic(magic));
    }

    let version = header[4];
    if version != FRAME_VERSION_V1 {
        return Err(IpcError::UnsupportedVersion(version));
    }

    let msg_type = MessageType::try_from(header[5])?;
    let declared_len = u32::from_be_bytes([header[6], header[7], header[8], header[9]]);
    let payload_len = usize::try_from(declared_len).map_err(|_| IpcError::FrameTooLarge {
        declared_len,
        max_len: MAX_FRAME_BYTES,
    })?;

    if payload_len > MAX_FRAME_BYTES {
        return Err(IpcError::FrameTooLarge {
            declared_len,
            max_len: MAX_FRAME_BYTES,
        });
    }

    Ok((msg_type, payload_len))
}

/// Reads a single bounded [`WireFrame`] within `deadline`, enforcing
/// `MAX_FRAME_BYTES` prior to heap allocation.
pub async fn read_bounded_frame<R>(
    reader: &mut R,
    deadline: Duration,
) -> Result<WireFrame, IpcError>
where
    R: AsyncRead + Unpin,
{
    tokio::time::timeout(deadline, async {
        let mut header = [0u8; FRAME_HEADER_LEN];
        reader
            .read_exact(&mut header)
            .await
            .map_err(map_read_error)?;

        let (msg_type, payload_len) = parse_frame_header(&header)?;
        let mut payload = Vec::new();
        if payload_len > 0 {
            payload
                .try_reserve_exact(payload_len)
                .map_err(|e| IpcError::IoError(format!("frame allocation failed: {e}")))?;
            payload.resize(payload_len, 0u8);
            reader
                .read_exact(&mut payload)
                .await
                .map_err(map_read_error)?;
        }

        Ok(WireFrame { msg_type, payload })
    })
    .await
    .map_err(|_| IpcError::FrameTimeout)?
}

/// Writes a single bounded [`WireFrame`] within `deadline`.
pub async fn write_bounded_frame<W>(
    writer: &mut W,
    frame: &WireFrame,
    deadline: Duration,
) -> Result<(), IpcError>
where
    W: AsyncWrite + Unpin,
{
    let encoded = frame.encode()?;
    tokio::time::timeout(deadline, async {
        writer
            .write_all(&encoded)
            .await
            .map_err(|e| IpcError::IoError(e.to_string()))?;
        writer
            .flush()
            .await
            .map_err(|e| IpcError::IoError(e.to_string()))?;
        Ok(())
    })
    .await
    .map_err(|_| IpcError::FrameTimeout)?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_over_duplex_stream() {
        let (mut client, mut server) = tokio::io::duplex(16_384);
        let outbound = WireFrame {
            msg_type: MessageType::CommandRequest,
            payload: b"ping-control-plane".to_vec(),
        };

        write_bounded_frame(&mut client, &outbound, Duration::from_secs(1))
            .await
            .unwrap();
        let inbound = read_bounded_frame(&mut server, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(inbound, outbound);
    }
}
