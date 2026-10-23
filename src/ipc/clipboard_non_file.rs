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
        let mut contents = Vec::new();
        contents.try_reserve_exact(clipboards.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let mut raw_chunks = Vec::new();
        for clipboard in clipboards {
            let content_len = clipboard.content.len();
            let next_raw = content_len > Self::INLINE_CONTENT_BYTES;
            let content = if next_raw {
                raw_chunks.try_reserve(1)
                    .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
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
        let mut raw = Vec::new();
        raw.try_reserve_exact(raw_len)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        for chunk in raw_chunks {
            raw.extend_from_slice(&chunk);
        }
        Ok((contents, raw.into()))
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
        let mut clipboards = Vec::new();
        clipboards.try_reserve_exact(contents.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        for item in &mut contents {
            if item.next_raw {
                item.content = raw.split_to(item.content_len).freeze();
            }
        }
        for item in contents {
            let format = item.format()?.into();
            clipboards.push(Clipboard {
                compress: item.compress,
                content: item.content,
                width: item.width,
                height: item.height,
                format,
                special_name: item.special_name,
                ..Default::default()
            });
        }
        Ok(clipboards)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    mod allocations {
        use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell};

        thread_local! {
            static STATE: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
        }

        fn refuse() -> bool {
            STATE.try_with(|state| {
                let (target, count) = state.get();
                if target == 0 {
                    return false;
                }
                state.set((target, count + 1));
                count + 1 == target
            }).unwrap_or(false)
        }

        struct Allocator;

        unsafe impl GlobalAlloc for Allocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                if refuse() { std::ptr::null_mut() } else { System.alloc(layout) }
            }

            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                if refuse() { std::ptr::null_mut() } else { System.alloc_zeroed(layout) }
            }

            unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                if refuse() { std::ptr::null_mut() } else { System.realloc(pointer, layout, size) }
            }

            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                System.dealloc(pointer, layout)
            }
        }

        #[global_allocator]
        static ALLOCATOR: Allocator = Allocator;

        pub(super) fn observe<T>(target: usize, action: impl FnOnce() -> T) -> (T, usize) {
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) { STATE.with(|state| state.set((0, 0))); }
            }
            STATE.with(|state| {
                assert_eq!(state.get(), (0, 0));
                state.set((target, 0));
            });
            let reset = Reset;
            let result = action();
            let count = STATE.with(|state| state.get().1);
            drop(reset);
            (result, count)
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn producer_allocation_refusal_preserves_exact_retry() {
        use std::{os::unix::process::ExitStatusExt, process::Command};
        use allocations::observe;

        const RAW: &[u8] = &[b'x'; ClipboardNonFile::INLINE_CONTENT_BYTES + 1];
        fn source(count: usize, raw: bool) -> Vec<Clipboard> {
            (0..count).map(|index| Clipboard {
                content: Bytes::from_static(if raw { RAW } else { b"inline" }),
                compress: index % 2 == 0,
                width: index as i32,
                height: -(index as i32),
                format: ClipboardFormat::Html.into(),
                special_name: format!("format-{index}"),
                ..Default::default()
            }).collect()
        }

        if let Ok(case) = std::env::var("RD_CLIPBOARD_PREPARE_ALLOC_CASE") {
            if case == "probe" {
                observe(1, || std::hint::black_box(Vec::<u8>::with_capacity(64)));
                panic!("allocation-refusal probe did not abort");
            }
            let target: usize = case.parse().unwrap();
            assert!((1..=5).contains(&target));
            let input = source(MAX_NATIVE_CLIPBOARD_ITEMS, true);
            let expected = input.clone();
            let (result, count) = observe(target, || ClipboardNonFile::prepare_contents(input));
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::OutOfMemory);
            assert_eq!(count, target);
            let (metadata, raw) = ClipboardNonFile::prepare_contents(expected.clone()).unwrap();
            assert_eq!(ClipboardNonFile::restore_raw_contents(metadata, raw.into()).unwrap(), expected);
            println!("CLIPBOARD_PREPARE_ALLOC_CASE=observed fail_at={target} allocations={count} error=OutOfMemory retry_exact=true");
            return;
        }

        for (items, raw) in [(0, false), (1, false), (1, true), (MAX_NATIVE_CLIPBOARD_ITEMS, true)] {
            let input = source(items, raw);
            let expected = input.clone();
            let (result, count) = observe(usize::MAX, || ClipboardNonFile::prepare_contents(input));
            let (metadata, raw_bytes) = result.unwrap();
            let expected_count = match (items, raw) { (0, _) => 0, (_, false) => 1, (1, true) => 3, _ => 5 };
            assert_eq!(count, expected_count);
            assert_eq!(ClipboardNonFile::restore_raw_contents(metadata, raw_bytes.into()).unwrap(), expected);
            println!("CLIPBOARD_PREPARE_ALLOC_CONTROL=observed items={items} raw={raw} allocations={count} exact=true");
        }

        let thread = std::thread::current();
        let name = thread.name().unwrap();
        let run = |case: &str| Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("RD_CLIPBOARD_PREPARE_ALLOC_CASE", case)
            .output().unwrap();
        let probe = run("probe");
        let probe_ok = probe.status.signal() == Some(6)
            && String::from_utf8_lossy(&probe.stderr).contains("memory allocation of");
        println!("CLIPBOARD_PREPARE_ALLOC_PROBE=observed signal={:?} passed={probe_ok}", probe.status.signal());
        let mut all_ok = probe_ok;
        for target in 1..=5 {
            let output = run(&target.to_string());
            let records: Vec<_> = String::from_utf8_lossy(&output.stdout).lines()
                .filter_map(|line| line.split_once("CLIPBOARD_PREPARE_ALLOC_CASE=").map(|(_, value)| value.to_owned())).collect();
            for record in &records { println!("CLIPBOARD_PREPARE_ALLOC_CASE={record}"); }
            let expected = format!("observed fail_at={target} allocations={target} error=OutOfMemory retry_exact=true");
            let correct = output.status.success() && records == [expected];
            print!("{}", String::from_utf8_lossy(&output.stderr));
            println!("CLIPBOARD_PREPARE_ALLOC_CHILD=observed fail_at={target} success={} signal={:?} correct={correct}",
                output.status.success(), output.status.signal());
            all_ok &= correct;
        }
        assert!(all_ok, "clipboard response allocation failure must be recoverable");
        println!("CLIPBOARD_PREPARE_ALLOC=pass refusal_points=5 refusals=5 controls=4 probe=SIGABRT children=joined");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn framed_receiver_allocation_refusal_preserves_exact_contents() {
        use hbb_common::{bytes_codec::BytesCodec, tokio_util::codec::{Decoder, Encoder}};
        use std::{os::unix::process::ExitStatusExt, process::Command};
        use allocations::observe;

        fn exercise(case: &str, refuse: bool) -> (usize, bool) {
            const RAW: &[u8] = &[b'x'; ClipboardNonFile::INLINE_CONTENT_BYTES + 1];
            let count = match case { "empty" => 0, "sixteen" => MAX_NATIVE_CLIPBOARD_ITEMS, "mixed" => 4, _ => 1 };
            let expected: Vec<_> = (0..count).map(|index| Clipboard {
                content: Bytes::from_static(if case == "inline" || (case == "mixed" && index % 2 == 0) {
                    b"inline"
                } else { RAW }),
                compress: index % 2 == 0,
                width: index as i32,
                height: -(index as i32),
                format: ClipboardFormat::Html.into(),
                special_name: format!("format-{index}"),
                ..Default::default()
            }).collect();
            let (metadata, payload) = ClipboardNonFile::prepare_contents(expected.clone()).unwrap();
            let mut codec = BytesCodec::new();
            codec.set_max_packet_length(ClipboardNonFile::METADATA_FRAME_BYTES);
            let mut wire = BytesMut::new();
            let raw = if payload.is_empty() {
                BytesMut::new()
            } else {
                codec.encode(payload, &mut wire).unwrap();
                codec.encode(Bytes::from_static(b"next-frame"), &mut wire).unwrap();
                codec.decode(&mut wire).unwrap().unwrap()
            };
            let raw_ptr = raw.as_ptr();
            let (result, count) = observe(if refuse { 1 } else { usize::MAX }, || {
                ClipboardNonFile::restore_raw_contents(metadata, raw)
            });
            let refused = match result {
                Ok(restored) => {
                    assert_eq!(restored, expected);
                    let mut offset = 0;
                    for clipboard in &restored {
                        if clipboard.content.len() > ClipboardNonFile::INLINE_CONTENT_BYTES {
                            assert_eq!(clipboard.content.as_ptr(), raw_ptr.wrapping_add(offset));
                            offset += clipboard.content.len();
                        }
                    }
                    false
                }
                Err(error) => {
                    assert!(refuse);
                    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
                    true
                }
            };
            if wire.is_empty() {
                assert!(case == "empty" || case == "inline");
            } else {
                assert_eq!(codec.decode(&mut wire).unwrap().unwrap().as_ref(), b"next-frame");
                assert!(wire.is_empty());
            }
            if refuse { assert_eq!(count, usize::from(refused)); }
            (count, refused)
        }

        if let Ok(case) = std::env::var("RD_CLIPBOARD_RESTORE_ALLOC_CASE") {
            if case == "probe" {
                observe(1, || std::hint::black_box(Vec::<u8>::with_capacity(64)));
                panic!("allocation-refusal probe did not abort");
            }
            assert!(["empty", "inline", "raw", "mixed", "sixteen"].contains(&case.as_str()));
            let (count, refused) = exercise(&case, true);
            exercise(&case, false);
            println!("CLIPBOARD_RESTORE_ALLOC_CASE=observed case={case} allocations={count} refused={refused} retry_exact=true zero_copy=true coalesced=true");
            return;
        }

        let thread = std::thread::current();
        let name = thread.name().unwrap();
        let run = |case: &str| Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env("RD_CLIPBOARD_RESTORE_ALLOC_CASE", case)
            .output().unwrap();
        let probe = run("probe");
        let probe_ok = probe.status.signal() == Some(6)
            && String::from_utf8_lossy(&probe.stderr).contains("memory allocation of");
        println!("CLIPBOARD_RESTORE_ALLOC_PROBE=observed signal={:?} passed={probe_ok}", probe.status.signal());
        let mut all_ok = probe_ok;
        for case in ["empty", "inline", "raw", "mixed", "sixteen"] {
            let output = run(case);
            let records: Vec<_> = String::from_utf8_lossy(&output.stdout).lines()
                .filter_map(|line| line.split_once("CLIPBOARD_RESTORE_ALLOC_CASE=").map(|(_, value)| value.to_owned())).collect();
            for record in &records { println!("CLIPBOARD_RESTORE_ALLOC_CASE={record}"); }
            let correct = output.status.success() && records.len() == 1
                && records[0].starts_with(&format!("observed case={case} allocations="))
                && records[0].ends_with(" retry_exact=true zero_copy=true coalesced=true");
            print!("{}", String::from_utf8_lossy(&output.stderr));
            println!("CLIPBOARD_RESTORE_ALLOC_CHILD=observed case={case} success={} signal={:?} correct={correct}",
                output.status.success(), output.status.signal());
            all_ok &= correct;
        }
        assert!(all_ok, "framed clipboard receive must recover from refused output storage");
        println!("CLIPBOARD_RESTORE_ALLOC=pass cases=5 retry=exact zero_copy=true coalesced=true probe=SIGABRT children=joined");
    }

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
