use bytes::{Bytes, BytesMut};
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
    fn format(&self) -> io::Result<ClipboardFormat> {
        ClipboardFormat::from_i32(self.format).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "unknown CM clipboard format")
        })
    }

    pub(crate) fn raw_content_len(contents: &[Self]) -> io::Result<usize> {
        contents.iter().try_fold(0usize, |total, item| {
            item.format()?;
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
            } else if item.content.len() != item.content_len {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "inline clipboard length differs from metadata",
                ))
            } else {
                Ok(total)
            }
        })
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
}
