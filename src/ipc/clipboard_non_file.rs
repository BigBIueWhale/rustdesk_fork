use bytes::{Bytes, BytesMut};
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
    pub(crate) fn raw_content_len(contents: &[Self]) -> io::Result<usize> {
        contents.iter().try_fold(0usize, |total, item| {
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
    ) -> io::Result<Vec<Self>> {
        if Self::raw_content_len(&contents)? != raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "raw clipboard length differs from metadata",
            ));
        }
        for item in &mut contents {
            if item.next_raw {
                item.content = raw.split_to(item.content_len).freeze();
                item.next_raw = false;
            }
        }
        Ok(contents)
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
        assert!(restored.iter().all(|item| !item.next_raw));
        assert_eq!(ClipboardNonFile::raw_content_len(&restored).unwrap(), 0);
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
}
