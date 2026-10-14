use bytes::{Bytes, BytesMut};
use crate::clipboard::limits::{
    MAX_NATIVE_CLIPBOARD_ITEMS, MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES,
    MAX_NATIVE_CLIPBOARD_TOTAL_BYTES,
};
use hbb_common::{
    message_proto::{Clipboard, ClipboardFormat},
    protobuf::Enum,
};
use serde_derive::{Deserialize, Serialize};
use std::io;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "t")]
pub struct ClipboardNonFile {
    pub compress: bool,
    pub content: Bytes,
    pub content_len: usize,
    pub next_raw: bool,
    pub width: i32,
    pub height: i32,
    // message.proto: ClipboardFormat
    pub format: i32,
    pub special_name: String,
}

impl ClipboardNonFile {
    pub(crate) const INLINE_CONTENT_BYTES: usize = 3 * 1024;
    pub(crate) const METADATA_FRAME_BYTES: usize = 256 * 1024;

    pub(crate) fn prepare_contents(clipboards: Vec<Clipboard>) -> io::Result<(Vec<Self>, Bytes)> {
        if clipboards.len() > MAX_NATIVE_CLIPBOARD_ITEMS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many CM clipboard items"));
        }
        let mut contents = Vec::with_capacity(clipboards.len());
        let mut raw_chunks = Vec::new();
        for clipboard in clipboards {
            let content_len = clipboard.content.len();
            let next_raw = content_len > Self::INLINE_CONTENT_BYTES;
            let content = if next_raw {
                raw_chunks.push(clipboard.content);
                Bytes::new()
            } else {
                clipboard.content
            };
            contents.push(Self {
                compress: clipboard.compress,
                content,
                content_len,
                next_raw,
                width: clipboard.width,
                height: clipboard.height,
                format: clipboard.format.value(),
                special_name: clipboard.special_name,
            });
        }
        let raw_len = Self::raw_content_len(&contents)?;
        let mut raw = BytesMut::with_capacity(raw_len);
        for chunk in raw_chunks {
            raw.extend_from_slice(&chunk);
        }
        Ok((contents, raw.freeze()))
    }

    fn format(&self) -> io::Result<ClipboardFormat> {
        ClipboardFormat::from_i32(self.format).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unknown CM clipboard format")
        })
    }

    pub(crate) fn raw_content_len(contents: &[Self]) -> io::Result<usize> {
        if contents.len() > MAX_NATIVE_CLIPBOARD_ITEMS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many CM clipboard items"));
        }
        let mut content_total = 0usize;
        let raw_total = contents.iter().try_fold(0usize, |total, item| {
            item.format()?;
            if item.special_name.len() > MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "CM clipboard format name too long"));
            }
            content_total = content_total.checked_add(item.content_len).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "CM clipboard content length overflow")
            })?;
            if item.next_raw {
                if !item.content.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "raw clipboard item also contains inline bytes",
                    ));
                }
                total.checked_add(item.content_len).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "raw clipboard length overflow")
                })
            } else if item.content.len() != item.content_len
                || item.content.len() > Self::INLINE_CONTENT_BYTES
            {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid CM inline clipboard length",
                ))
            } else {
                Ok(total)
            }
        })?;
        if content_total > MAX_NATIVE_CLIPBOARD_TOTAL_BYTES {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "CM clipboard content exceeds limit"));
        }
        Ok(raw_total)
    }

    pub(crate) fn restore_raw_contents(
        mut contents: Vec<Self>,
        mut raw: BytesMut,
    ) -> io::Result<Vec<Clipboard>> {
        if Self::raw_content_len(&contents)? != raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "raw clipboard length differs from metadata",
            ));
        }
        for item in &mut contents {
            if item.next_raw {
                item.content = raw.split_to(item.content_len).freeze();
            }
        }
        contents.into_iter().map(|item| {
            let format = item.format()?.into();
            Ok(Clipboard {
                compress: item.compress,
                content: item.content,
                width: item.width,
                height: item.height,
                format,
                special_name: item.special_name,
                ..Default::default()
            })
        }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(content: &'static [u8], content_len: usize, next_raw: bool) -> ClipboardNonFile {
        ClipboardNonFile {
            compress: false,
            content: Bytes::from_static(content),
            content_len,
            next_raw,
            width: 0,
            height: 0,
            format: 0,
            special_name: String::new(),
        }
    }

    #[test]
    fn mixed_inline_and_raw_items_restore_exact_bytes() {
        let raw = BytesMut::from(&b"abcdef"[..]);
        let ptr = raw.as_ptr();
        let restored = ClipboardNonFile::restore_raw_contents(
            vec![item(b"inline", 6, false), item(b"", 2, true), item(b"", 4, true)],
            raw,
        ).unwrap();
        assert_eq!(restored[0].content.as_ref(), b"inline");
        assert_eq!(restored[1].content.as_ref(), b"ab");
        assert_eq!(restored[2].content.as_ref(), b"cdef");
        assert_eq!(restored[1].content.as_ptr(), ptr);
        assert!(restored.iter().all(|item| item.format.enum_value().unwrap() == ClipboardFormat::Text));
    }

    #[test]
    fn short_raw_reply_refuses_without_panicking() {
        let result = ClipboardNonFile::restore_raw_contents(
            vec![item(b"", 2, true), item(b"", 4, true)],
            BytesMut::from(&b"abcde"[..]),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn trailing_raw_bytes_refuse_the_complete_reply() {
        let result = ClipboardNonFile::restore_raw_contents(
            vec![item(b"", 2, true)], BytesMut::from(&b"abc"[..]),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn metadata_length_overflow_refuses_before_splitting() {
        let contents = vec![item(b"", usize::MAX, true), item(b"", 1, true)];
        assert!(ClipboardNonFile::raw_content_len(&contents).is_err());
        assert!(ClipboardNonFile::restore_raw_contents(contents, BytesMut::new()).is_err());
    }

    #[test]
    fn inline_length_mismatch_refuses_the_complete_reply() {
        let result = ClipboardNonFile::restore_raw_contents(
            vec![item(b"", 1, true), item(b"inline", 5, false)],
            BytesMut::from(&b"a"[..]),
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn raw_item_cannot_also_supply_inline_content() {
        assert!(ClipboardNonFile::raw_content_len(&[item(b"inline", 6, true)]).is_err());
    }

    #[test]
    fn empty_and_inline_only_replies_need_no_raw_frame() {
        assert!(ClipboardNonFile::restore_raw_contents(vec![], BytesMut::new()).unwrap().is_empty());
        let contents = vec![item(b"", 0, true), item(b"inline", 6, false)];
        let restored = ClipboardNonFile::restore_raw_contents(contents, BytesMut::new()).unwrap();
        assert!(restored[0].content.is_empty());
        assert_eq!(restored[1].content.as_ref(), b"inline");
    }

    #[test]
    fn response_metadata_retains_its_serialized_wire_shape() {
        let encoded = serde_json::to_value(item(b"abc", 3, false)).unwrap();
        assert_eq!(encoded, serde_json::json!({
            "t": "ClipboardNonFile", "compress": false, "content": [97, 98, 99],
            "content_len": 3, "next_raw": false, "width": 0, "height": 0,
            "format": 0, "special_name": ""
        }));
        let decoded: ClipboardNonFile = serde_json::from_value(encoded).unwrap();
        assert_eq!(ClipboardNonFile::raw_content_len(&[decoded]).unwrap(), 0);
    }

    #[test]
    fn unknown_format_refuses_the_complete_reply() {
        for format in [-1, 3, 20, 24, 32, i32::MAX] {
            let mut unknown = item(b"invalid", 7, false);
            unknown.format = format;
            let contents = vec![item(b"valid", 5, false), unknown];
            assert!(ClipboardNonFile::raw_content_len(&contents).is_err());
            let error = ClipboardNonFile::restore_raw_contents(contents, BytesMut::new()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn declared_formats_preserve_payload_and_metadata() {
        assert_eq!(ClipboardFormat::VALUES.len(), 7);
        for &format in ClipboardFormat::VALUES {
            let mut source = item(b"abcdefgh", 8, false);
            source.format = format.value();
            source.width = 2;
            source.height = 1;
            source.special_name = "XML Spreadsheet".to_owned();
            let restored = ClipboardNonFile::restore_raw_contents(vec![source], BytesMut::new()).unwrap();
            assert_eq!(restored[0].format.enum_value().unwrap(), format);
            assert_eq!(restored[0].content.as_ref(), b"abcdefgh");
            assert_eq!((restored[0].width, restored[0].height), (2, 1));
            assert_eq!(restored[0].special_name, "XML Spreadsheet");
            assert!(!restored[0].compress);
        }
    }

    #[test]
    fn raw_json_reply_roundtrips_through_the_production_protobuf() {
        use hbb_common::protobuf::Message as _;
        let raw = vec![b'x'; 4096];
        let mut source = item(b"", raw.len(), true);
        source.format = ClipboardFormat::Html.value();
        let encoded = serde_json::to_vec(&source).unwrap();
        let decoded = serde_json::from_slice(&encoded).unwrap();
        let restored = ClipboardNonFile::restore_raw_contents(vec![decoded], BytesMut::from(raw.as_slice())).unwrap();
        let wire = restored[0].write_to_bytes().unwrap();
        let parsed = Clipboard::parse_from_bytes(&wire).unwrap();
        assert_eq!(parsed.format.enum_value().unwrap(), ClipboardFormat::Html);
        assert_eq!(parsed.content.as_ref(), raw.as_slice());
        assert!(!parsed.compress);
    }

    #[test]
    fn metadata_item_count_is_bounded() {
        let allowed = vec![item(b"", 0, false); MAX_NATIVE_CLIPBOARD_ITEMS];
        assert_eq!(ClipboardNonFile::raw_content_len(&allowed).unwrap(), 0);
        let excess = vec![item(b"", 0, false); MAX_NATIVE_CLIPBOARD_ITEMS + 1];
        assert!(ClipboardNonFile::raw_content_len(&excess).is_err());
    }

    #[test]
    fn metadata_total_counts_inline_and_raw_bytes() {
        let raw = item(b"", MAX_NATIVE_CLIPBOARD_TOTAL_BYTES, true);
        assert_eq!(ClipboardNonFile::raw_content_len(&[raw.clone()]).unwrap(), MAX_NATIVE_CLIPBOARD_TOTAL_BYTES);
        assert!(ClipboardNonFile::raw_content_len(&[raw, item(b"a", 1, false)]).is_err());
        assert!(ClipboardNonFile::raw_content_len(&[item(b"", MAX_NATIVE_CLIPBOARD_TOTAL_BYTES + 1, true)]).is_err());
    }

    #[test]
    fn inline_payload_obeys_the_producer_threshold() {
        let mut allowed = item(b"", ClipboardNonFile::INLINE_CONTENT_BYTES, false);
        allowed.content = vec![b'x'; allowed.content_len].into();
        assert_eq!(ClipboardNonFile::raw_content_len(&[allowed]).unwrap(), 0);
        let mut excess = item(b"", ClipboardNonFile::INLINE_CONTENT_BYTES + 1, false);
        excess.content = vec![b'x'; excess.content_len].into();
        assert!(ClipboardNonFile::raw_content_len(&[excess]).is_err());
    }

    #[test]
    fn format_name_limit_counts_utf8_bytes() {
        let mut source = item(b"", 0, false);
        source.special_name = "é".repeat(MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES / 2);
        assert_eq!(ClipboardNonFile::raw_content_len(&[source.clone()]).unwrap(), 0);
        source.special_name.push('x');
        assert!(ClipboardNonFile::raw_content_len(&[source]).is_err());
    }

    #[test]
    fn exact_maximum_raw_reply_restores_without_copy() {
        let mut raw = BytesMut::new();
        raw.resize(MAX_NATIVE_CLIPBOARD_TOTAL_BYTES, b'x');
        let ptr = raw.as_ptr();
        let restored = ClipboardNonFile::restore_raw_contents(
            vec![item(b"", raw.len(), true)], raw,
        ).unwrap();
        assert_eq!(restored[0].content.len(), MAX_NATIVE_CLIPBOARD_TOTAL_BYTES);
        assert_eq!(restored[0].content.as_ptr(), ptr);
        assert_eq!(restored[0].content[0], b'x');
        assert_eq!(restored[0].content[MAX_NATIVE_CLIPBOARD_TOTAL_BYTES - 1], b'x');
    }

    #[test]
    fn worst_case_metadata_fits_its_codec_budget() {
        let mut source = item(b"", ClipboardNonFile::INLINE_CONTENT_BYTES, false);
        source.content = vec![255; source.content_len].into();
        source.special_name = "\0".repeat(MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES);
        source.width = i32::MIN;
        source.height = i32::MIN;
        let contents = vec![source; MAX_NATIVE_CLIPBOARD_ITEMS];
        assert_eq!(ClipboardNonFile::raw_content_len(&contents).unwrap(), 0);
        let encoded = serde_json::to_vec(&(String::new(), contents)).unwrap();
        assert!(encoded.len() + 1024 < ClipboardNonFile::METADATA_FRAME_BYTES);
    }

    #[test]
    fn codec_rejects_oversized_metadata_and_raw_headers_before_reserve() {
        use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::{Decoder, Encoder}};
        for (limit, advertised) in [
            (ClipboardNonFile::METADATA_FRAME_BYTES, ClipboardNonFile::METADATA_FRAME_BYTES + 1),
            (8, 9),
        ] {
            let mut encoder = BytesCodec::new();
            let mut wire = BytesMut::new();
            encoder.encode(vec![0; advertised].into(), &mut wire).unwrap();
            let header_len = ((wire[0] & 3) + 1) as usize;
            let mut input = BytesMut::from(&wire[..header_len]);
            let capacity = input.capacity();
            let mut decoder = BytesCodec::new();
            decoder.set_max_packet_length(limit);
            assert_eq!(decoder.decode(&mut input).unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert_eq!(input.capacity(), capacity);
            assert_eq!(input.as_ref(), &wire[..header_len]);
        }
    }

    #[test]
    fn codec_phase_limits_preserve_buffered_frame_order() {
        use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::{Decoder, Encoder}};
        let mut encoder = BytesCodec::new();
        let mut input = BytesMut::new();
        for data in [b"first-header".as_slice(), b"abcdefgh".as_slice(), b"next-header".as_slice()] {
            encoder.encode(Bytes::copy_from_slice(data), &mut input).unwrap();
        }
        let mut decoder = BytesCodec::new();
        decoder.set_max_packet_length(ClipboardNonFile::METADATA_FRAME_BYTES);
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap().as_ref(), b"first-header");
        let contents = vec![item(b"", 8, true)];
        decoder.set_max_packet_length(ClipboardNonFile::raw_content_len(&contents).unwrap());
        let raw = decoder.decode(&mut input).unwrap().unwrap();
        let restored = ClipboardNonFile::restore_raw_contents(contents, raw).unwrap();
        assert_eq!(restored[0].content.as_ref(), b"abcdefgh");
        decoder.set_max_packet_length(ClipboardNonFile::METADATA_FRAME_BYTES);
        assert_eq!(decoder.decode(&mut input).unwrap().unwrap().as_ref(), b"next-header");
        assert!(input.is_empty());
    }

    #[test]
    fn producer_and_receiver_preserve_inline_and_raw_entries() {
        let small = Clipboard { content: Bytes::from_static(b"small"), ..Default::default() };
        let large = Clipboard { content: vec![b'x'; ClipboardNonFile::INLINE_CONTENT_BYTES + 1].into(),
            format: ClipboardFormat::Html.into(), ..Default::default() };
        let (contents, raw) = ClipboardNonFile::prepare_contents(vec![small, large]).unwrap();
        assert_eq!(contents[0].content.as_ref(), b"small");
        assert!(!contents[0].next_raw);
        assert!(contents[1].content.is_empty());
        assert!(contents[1].next_raw);
        assert_eq!(raw.len(), ClipboardNonFile::INLINE_CONTENT_BYTES + 1);
        let restored = ClipboardNonFile::restore_raw_contents(contents, raw.into()).unwrap();
        assert_eq!(restored[0].content.as_ref(), b"small");
        assert_eq!(restored[1].content.len(), ClipboardNonFile::INLINE_CONTENT_BYTES + 1);
        assert_eq!(restored[1].format.enum_value().unwrap(), ClipboardFormat::Html);
        assert!(restored[1].content.iter().all(|byte| *byte == b'x'));
    }

    #[test]
    fn producer_refuses_out_of_policy_metadata() {
        let mut invalid = Clipboard::new();
        invalid.special_name = "x".repeat(MAX_NATIVE_CLIPBOARD_SPECIAL_NAME_BYTES + 1);
        assert!(ClipboardNonFile::prepare_contents(vec![invalid]).is_err());
        assert!(ClipboardNonFile::prepare_contents(vec![Clipboard::new(); MAX_NATIVE_CLIPBOARD_ITEMS + 1]).is_err());
    }
}
