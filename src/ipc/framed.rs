use bytes::{Bytes, BytesMut};
use hbb_common::{
    bytes_codec::BytesCodec,
    tokio::io::{AsyncRead, AsyncReadExt},
    tokio_util::codec::Decoder,
};
use std::io;

pub(super) struct IpcFrameReader<T> {
    inner: T,
    codec: BytesCodec,
    buffer: BytesMut,
    terminal: bool,
}

impl<T: AsyncRead + Unpin> IpcFrameReader<T> {
    pub(super) fn new(inner: T, codec: BytesCodec) -> Self {
        Self { inner, codec, buffer: BytesMut::new(), terminal: false }
    }

    pub(super) fn get_ref(&self) -> &T {
        &self.inner
    }

    pub(super) fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    pub(super) fn decoder(&self) -> &BytesCodec {
        &self.codec
    }

    pub(super) fn decoder_mut(&mut self) -> &mut BytesCodec {
        &mut self.codec
    }

    pub(super) async fn next(&mut self) -> Option<io::Result<BytesMut>> {
        if self.terminal {
            return None;
        }
        match self.read_frame().await {
            Ok(Some(frame)) => Some(Ok(frame)),
            result => {
                self.terminal = true;
                self.buffer = BytesMut::new();
                result.err().map(Err)
            }
        }
    }

    async fn read_frame(&mut self) -> io::Result<Option<BytesMut>> {
        loop {
            if let Some(frame) = self.codec.decode(&mut self.buffer)? {
                return Ok(Some(frame));
            }
            // read() is cancellation-safe. Persist every received byte before
            // awaiting again; decoding state and partial input belong to self.
            let mut chunk = [0; 8192];
            let received = self.inner.read(&mut chunk).await?;
            if received == 0 {
                return self.codec.decode_eof(&mut self.buffer);
            }
            if !self.buffer.try_reclaim(received) {
                let required = self.buffer.len().checked_add(received).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "IPC buffer length overflow")
                })?;
                // Grow only for bytes actually received. The extra chunk bounds
                // read-ahead, including bytes belonging to the following frame.
                let capacity = self.buffer.capacity().saturating_mul(2).max(required)
                    .min(self.codec.max_packet_length().saturating_add(chunk.len()));
                if capacity < required {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Too big packet"));
                }
                let mut buffer = Vec::new();
                buffer.try_reserve_exact(capacity).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "inbound IPC frame allocation failed")
                })?;
                buffer.extend_from_slice(&self.buffer);
                // This newly owned backing has no other references. Conversion
                // transfers its payload; it must never fall back to copying it.
                self.buffer = Bytes::from(buffer).try_into_mut().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "IPC buffer ownership unavailable")
                })?;
            }
            self.buffer.extend_from_slice(&chunk[..received]);
        }
    }
}
