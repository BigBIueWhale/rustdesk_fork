use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

// Bound speculative allocation from untrusted frame headers.
const MAX_PREALLOCATED_PAYLOAD_LEN: usize = 256 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct BytesCodec {
    state: DecodeState,
    max_packet_length: usize,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Head,
    Data(usize),
}

impl Default for BytesCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl BytesCodec {
    pub fn new() -> Self {
        Self {
            state: DecodeState::Head,
            max_packet_length: usize::MAX,
        }
    }

    pub fn set_max_packet_length(&mut self, n: usize) {
        self.max_packet_length = n;
    }

    /// The engaged frame cap (R-A5: never `usize::MAX` on a keyed stream — the fail-closed assert
    /// at `FramedStream::set_session_keys` reads it back).
    pub fn max_packet_length(&self) -> usize {
        self.max_packet_length
    }

    fn decode_head(&mut self, src: &mut BytesMut) -> io::Result<Option<usize>> {
        if src.is_empty() {
            return Ok(None);
        }
        let head_len = ((src[0] & 0x3) + 1) as usize;
        if src.len() < head_len {
            return Ok(None);
        }
        let mut n = src[0] as usize;
        if head_len > 1 {
            n |= (src[1] as usize) << 8;
        }
        if head_len > 2 {
            n |= (src[2] as usize) << 16;
        }
        if head_len > 3 {
            n |= (src[3] as usize) << 24;
        }
        n >>= 2;
        if n > self.max_packet_length {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Too big packet"));
        }
        src.advance(head_len);
        // Do not reserve the full header-declared length: a peer can advertise a huge
        // frame and force excessive allocation before sending the payload.
        src.reserve(
            n.saturating_sub(src.len())
                .min(MAX_PREALLOCATED_PAYLOAD_LEN),
        );
        Ok(Some(n))
    }

    fn decode_data(&self, n: usize, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        if src.len() < n {
            return Ok(None);
        }
        Ok(Some(src.split_to(n)))
    }
}

impl Decoder for BytesCodec {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<BytesMut>, io::Error> {
        let n = match self.state {
            DecodeState::Head => match self.decode_head(src)? {
                Some(n) => {
                    self.state = DecodeState::Data(n);
                    n
                }
                None => return Ok(None),
            },
            DecodeState::Data(n) => n,
        };

        match self.decode_data(n, src)? {
            Some(data) => {
                self.state = DecodeState::Head;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<BytesMut>> {
        match self.decode(src)? {
            Some(frame) => Ok(Some(frame)),
            None if src.is_empty() && matches!(self.state, DecodeState::Head) => {
                Ok(None)
            }
            // A consumed header may leave an empty buffer while its payload is still missing.
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete frame at end of stream",
            )),
        }
    }
}

impl Encoder<Bytes> for BytesCodec {
    type Error = io::Error;

    fn encode(&mut self, data: Bytes, buf: &mut BytesMut) -> Result<(), io::Error> {
        if data.len() <= 0x3F {
            buf.put_u8((data.len() << 2) as u8);
        } else if data.len() <= 0x3FFF {
            buf.put_u16_le((data.len() << 2) as u16 | 0x1);
        } else if data.len() <= 0x3FFFFF {
            let h = (data.len() << 2) as u32 | 0x2;
            buf.put_u16_le((h & 0xFFFF) as u16);
            buf.put_u8((h >> 16) as u8);
        } else if data.len() <= 0x3FFFFFFF {
            buf.put_u32_le((data.len() << 2) as u32 | 0x3);
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Overflow"));
        }
        buf.extend(data);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_codec1() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3F, 1);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        let buf_saved = buf.clone();
        assert_eq!(buf.len(), 0x3F + 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F);
            assert_eq!(res[0], 1);
        } else {
            panic!();
        }
        let mut codec2 = BytesCodec::new();
        let mut buf2 = BytesMut::new();
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[0..1]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[1..]);
        if let Ok(Some(res)) = codec2.decode(&mut buf2) {
            assert_eq!(res.len(), 0x3F);
            assert_eq!(res[0], 1);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec2() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        assert!(codec.encode("".into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 1);
        bytes.resize(0x3F + 1, 2);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3F + 2 + 2);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0);
        } else {
            panic!();
        }
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F + 1);
            assert_eq!(res[0], 2);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec3() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3F - 1, 3);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3F + 1 - 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3F - 1);
            assert_eq!(res[0], 3);
        } else {
            panic!();
        }
    }
    #[test]
    fn test_codec4() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFF, 4);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3FFF + 2);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFF);
            assert_eq!(res[0], 4);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec5() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFFFF, 5);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        assert_eq!(buf.len(), 0x3FFFFF + 3);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFFFF);
            assert_eq!(res[0], 5);
        } else {
            panic!();
        }
    }

    #[test]
    fn test_codec6() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        let mut bytes: Vec<u8> = Vec::new();
        bytes.resize(0x3FFFFF + 1, 6);
        assert!(codec.encode(bytes.into(), &mut buf).is_ok());
        let buf_saved = buf.clone();
        assert_eq!(buf.len(), 0x3FFFFF + 4 + 1);
        if let Ok(Some(res)) = codec.decode(&mut buf) {
            assert_eq!(res.len(), 0x3FFFFF + 1);
            assert_eq!(res[0], 6);
        } else {
            panic!();
        }
        let mut codec2 = BytesCodec::new();
        let mut buf2 = BytesMut::new();
        buf2.extend(&buf_saved[0..1]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[1..6]);
        if let Ok(None) = codec2.decode(&mut buf2) {
        } else {
            panic!();
        }
        buf2.extend(&buf_saved[6..]);
        if let Ok(Some(res)) = codec2.decode(&mut buf2) {
            assert_eq!(res.len(), 0x3FFFFF + 1);
            assert_eq!(res[0], 6);
        } else {
            panic!();
        }
    }

    #[test]
    fn decode_headers_preserve_input_capacity_until_payload_arrives() {
        let mut cases = 0;
        let mut failures = 0;
        for (length, width) in [(1usize, 1), (64, 2), (16_384, 3), (4_194_304, 4), (0x3fff_ffff, 4)] {
            for limit in [length, usize::MAX] {
                for received in 0..length.min(2) {
                    let mut codec = BytesCodec::new();
                    codec.set_max_packet_length(limit);
                    let header = ((length << 2) as u32 | (width - 1) as u32).to_le_bytes();
                    let mut buf = BytesMut::from(&header[..width]);
                    let payload = vec![0x5a; received];
                    buf.extend_from_slice(&payload);
                    let before = buf.capacity();
                    let waiting = matches!(codec.decode(&mut buf), Ok(None));
                    let after = buf.capacity();
                    let repeated = (0..3).all(|_| matches!(codec.decode(&mut buf), Ok(None)));
                    let preserved = buf.as_ref() == payload.as_slice();
                    let bounded = after <= before && buf.capacity() == after;
                    let eof_refused = matches!(codec.decode_eof(&mut buf), Err(err)
                        if err.kind() == io::ErrorKind::UnexpectedEof);
                    let correct = waiting && repeated && preserved && bounded && eof_refused;
                    println!("BYTES_CODEC_HEADER_CASE=observed length={length} width={width} received={received} exact_limit={} capacity_before={before} capacity_after={after} waiting={waiting} repeated={repeated} payload_preserved={preserved} eof_refused={eof_refused} correct={correct}", limit == length);
                    failures += usize::from(!correct);
                    cases += 1;
                }
            }
        }
        assert_eq!(cases, 18);
        assert_eq!(failures, 0, "headers must not grow storage for absent payload bytes");
        println!("BYTES_CODEC_HEADER=pass cases=18 widths=4 cap_contexts=2 partial_payload=preserved eof=refused");
    }

    #[test]
    fn decode_rejects_oversized_frame_before_consuming_header() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();

        codec.set_max_packet_length(8);
        buf.put_u8(9 << 2);
        let capacity = buf.capacity();

        let err = codec.decode(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "Too big packet");
        assert_eq!(buf.as_ref(), &[9 << 2]);
        assert_eq!(buf.capacity(), capacity);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fragmented_tcp_frames_grow_from_received_payload_and_finish_cleanly() {
        use futures::TryStreamExt;
        use tokio::{
            io::AsyncWriteExt,
            net::{TcpListener, TcpStream},
            time::{timeout, Duration},
        };
        let expected = [
            Bytes::new(), Bytes::from_static(b"x"), Bytes::from(vec![0x42; 64]),
            Bytes::from(vec![0x43; 16_384]), Bytes::from(vec![0x44; 4_194_304]),
            Bytes::new(), Bytes::from_static(b"tail"), Bytes::new(),
        ];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sender = TcpStream::connect(listener.local_addr().unwrap()).await.unwrap();
        sender.set_nodelay(true).unwrap();
        let (receiver, _) = listener.accept().await.unwrap();
        drop(listener);
        let payloads = expected.clone();
        let mut writer = tokio::spawn(async move {
            let mut codec = BytesCodec::new();
            for payload in &payloads[..5] {
                let mut wire = BytesMut::new();
                codec.encode(payload.clone(), &mut wire)?;
                let width = ((wire[0] & 3) + 1) as usize;
                for byte in &wire[..width] {
                    sender.write_all(std::slice::from_ref(byte)).await?;
                    tokio::task::yield_now().await;
                }
                for chunk in wire[width..].chunks(8191) {
                    sender.write_all(chunk).await?;
                    tokio::task::yield_now().await;
                }
            }
            let mut coalesced = BytesMut::new();
            for payload in &payloads[5..] { codec.encode(payload.clone(), &mut coalesced)?; }
            sender.write_all(&coalesced).await?;
            sender.shutdown().await
        });
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(8 * 1024 * 1024);
        let read = timeout(Duration::from_secs(4),
            tokio_util::codec::FramedRead::new(receiver, codec).try_collect::<Vec<_>>()).await;
        let joined = match timeout(Duration::from_secs(4), &mut writer).await {
            Ok(joined) => joined,
            Err(_) => {
                writer.abort();
                let terminal = writer.await;
                panic!("fragmented frame sender exceeded its deadline: {terminal:?}");
            }
        };
        joined.unwrap().unwrap();
        let received = read.unwrap().unwrap();
        assert_eq!(received.len(), expected.len());
        for (actual, expected) in received.iter().zip(&expected) {
            assert_eq!(actual.as_ref(), expected.as_ref());
        }
        println!("BYTES_CODEC_TCP=pass frames=8 widths=4 fragmented_writes=true coalesced=true eof=clean sender=joined");
    }

    #[test]
    fn eof_rejects_partial_headers() {
        for width in 2..=4 {
            for received in 1..width {
                let mut codec = BytesCodec::new();
                let mut buf = BytesMut::from(&[width as u8 - 1, 1, 1][..received]);
                assert!(codec.decode(&mut buf).unwrap().is_none());
                assert_eq!(
                    codec.decode_eof(&mut buf).unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[test]
    fn eof_rejects_partial_payloads_after_consuming_each_header_width() {
        for (length, width) in [(1usize, 1), (64, 2), (16_384, 3), (4_194_304, 4)] {
            for received in 0..length.min(2) {
                let mut codec = BytesCodec::new();
                let header = ((length << 2) as u32 | (width - 1) as u32).to_le_bytes();
                let mut buf = BytesMut::from(&header[..width]);
                assert!(codec.decode(&mut buf).unwrap().is_none());
                assert!(buf.is_empty(), "the header is retained in decoder state");
                buf.extend_from_slice(&[0x5a][..received]);
                assert_eq!(
                    codec.decode_eof(&mut buf).unwrap_err().kind(),
                    io::ErrorKind::UnexpectedEof
                );
            }
        }
    }

    #[test]
    fn eof_preserves_complete_empty_coalesced_frames() {
        let mut codec = BytesCodec::new();
        let mut buf = BytesMut::new();
        for payload in [b"".as_slice(), b"message", b""] {
            codec
                .encode(Bytes::copy_from_slice(payload), &mut buf)
                .unwrap();
        }
        for payload in [b"".as_slice(), b"message", b""] {
            assert_eq!(&codec.decode_eof(&mut buf).unwrap().unwrap()[..], payload);
        }
        assert!(codec.decode_eof(&mut buf).unwrap().is_none());
    }

    #[test]
    fn eof_preserves_oversized_frame_refusal() {
        let mut codec = BytesCodec::new();
        codec.set_max_packet_length(8);
        let mut buf = BytesMut::from(&[9 << 2][..]);
        assert_eq!(
            codec.decode_eof(&mut buf).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
