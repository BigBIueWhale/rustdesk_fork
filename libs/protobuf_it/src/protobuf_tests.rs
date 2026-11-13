//! Direct generated-parser regressions. Transport framing and PAKE authorization
//! are separate boundaries; a successfully decoded protobuf grants neither.

use crate::{
    message_proto::{AudioFrame, CaptureDisplays, Cpace, CpaceStep1, CpaceStep2, CpaceStep3, CpaceStep4, Message},
    protobuf::Message as _,
};
use std::{alloc::{GlobalAlloc, Layout, System}, cell::Cell};

thread_local! {
    static ALLOCATIONS: Cell<(bool, usize, usize)> = const { Cell::new((false, 0, 0)) };
}

struct ObservedAllocator;

fn observe(size: usize) {
    let _ = ALLOCATIONS.try_with(|state| {
        let (armed, total, largest) = state.get();
        if armed {
            state.set((true, total.saturating_add(size), largest.max(size)));
        }
    });
}

unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        observe(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        observe(size);
        System.realloc(pointer, layout, size)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn measured<T>(action: impl FnOnce() -> T) -> (T, usize, usize) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ALLOCATIONS.with(|state| state.set((false, 0, 0)));
        }
    }
    assert!(!ALLOCATIONS.with(|state| state.replace((true, 0, 0))).0);
    let reset = Reset;
    let value = action();
    let (_, total, largest) = ALLOCATIONS.with(Cell::get);
    drop(reset);
    (value, total, largest)
}

#[test]
fn allocation_observer_counts_allocation_and_growth() {
    let (value, total, largest) = measured(|| {
        let mut value = std::hint::black_box(vec![0u8; 128 * 1024]);
        value.reserve_exact(128 * 1024);
        std::hint::black_box(value)
    });
    assert_eq!(value.len(), 128 * 1024);
    assert!(total >= 384 * 1024);
    assert!(largest >= 256 * 1024);
}

fn reject_length<M: crate::protobuf::Message>(bytes: &[u8]) {
    let (result, total, largest) = measured(|| M::parse_from_bytes(bytes));
    assert!(result.is_err(), "{} accepted {bytes:02x?}", M::NAME);
    // This bound applies to these tiny malformed-length fixtures, not to every
    // decoded frame. Observe requested allocations, including reallocations.
    assert!(total <= 4096, "{} requested {total} bytes, largest {largest}", M::NAME);
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    while value >= 128 {
        bytes.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    bytes.push(value as u8);
    bytes
}

fn field(field_number: u64, declared: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes = varint(field_number << 3 | 2);
    bytes.extend(varint(declared));
    bytes.extend_from_slice(body);
    bytes
}

fn groups_then(body: &[u8], depth: usize) -> Vec<u8> {
    // Field 100 is unknown in both production schemas. Groups still consume the
    // parser's recursion budget even though neither schema declares a group.
    let mut bytes = Vec::new();
    for _ in 0..depth {
        bytes.extend_from_slice(&[0xa3, 0x06]);
    }
    for _ in 0..depth {
        bytes.extend_from_slice(&[0xa4, 0x06]);
    }
    bytes.extend_from_slice(body);
    bytes
}

fn cpace() -> Cpace {
    let mut message = Cpace::new();
    message.set_step1(CpaceStep1 {
        sid_a: vec![0xa1; 16].into(),
        ad_a: b"viewer".to_vec().into(),
        ..Default::default()
    });
    message
}

fn post_key() -> Message {
    let mut message = Message::new();
    message.set_audio_frame(AudioFrame {
        data: vec![0x00, 0x80, 0xff].into(),
        ..Default::default()
    });
    message
}

#[test]
fn valid_cpace_steps_preserve_exact_fields() {
    let first = cpace();
    let mut expected = vec![0x0a, 0x1a, 0x0a, 0x10];
    expected.extend_from_slice(&[0xa1; 16]);
    expected.extend_from_slice(&[0x12, 0x06]);
    expected.extend_from_slice(b"viewer");
    assert_eq!(first.write_to_bytes().unwrap(), expected);
    let mut second = Cpace::new();
    second.set_step2(CpaceStep2 {
        sid_b: vec![0xb2; 16].into(),
        ad_b: b"server".to_vec().into(),
        yb: vec![0x32; 32].into(),
        ..Default::default()
    });
    let mut third = Cpace::new();
    third.set_step3(CpaceStep3 {
        ya: vec![0x43; 32].into(),
        ta: vec![0x64; 64].into(),
        ..Default::default()
    });
    let mut fourth = Cpace::new();
    fourth.set_step4(CpaceStep4 {
        tb: vec![0x74; 64].into(),
        ..Default::default()
    });
    for message in [first, second, third, fourth] {
        assert_eq!(Cpace::parse_from_bytes(&message.write_to_bytes().unwrap()).unwrap(), message);
    }
}

#[test]
fn valid_post_key_messages_preserve_exact_fields() {
    let audio = post_key();
    assert_eq!(audio.write_to_bytes().unwrap(), [0x5a, 0x05, 0x0a, 0x03, 0x00, 0x80, 0xff]);
    assert_eq!(Message::parse_from_bytes(&audio.write_to_bytes().unwrap()).unwrap(), audio);
    let mut cursor = Message::new();
    cursor.set_cursor_id(u64::MAX);
    let mut encoded = vec![0x70];
    encoded.extend_from_slice(&[0xff; 9]);
    encoded.push(0x01);
    assert_eq!(cursor.write_to_bytes().unwrap(), encoded);
    assert_eq!(Message::parse_from_bytes(&encoded).unwrap(), cursor);
}

#[test]
fn unknown_groups_enforce_recursion_limit() {
    let pre = cpace();
    let post = post_key();
    for depth in [0, 1, 99, 100, 101, 102, 256, 1000] {
        let pre_bytes = groups_then(&pre.write_to_bytes().unwrap(), depth);
        let post_bytes = groups_then(&post.write_to_bytes().unwrap(), depth);
        assert!(pre_bytes.len() <= 4096);
        let pre_result = Cpace::parse_from_bytes(&pre_bytes);
        let post_result = Message::parse_from_bytes(&post_bytes);
        // The generated unknown-field helper skips the first group directly;
        // each nested group then consumes one runtime recursion level.
        if depth <= 101 {
            assert_eq!(pre_result.unwrap(), pre, "pre-key depth {depth}");
            assert_eq!(post_result.unwrap(), post, "post-key depth {depth}");
        } else {
            assert!(pre_result.is_err(), "pre-key depth {depth}");
            assert!(post_result.is_err(), "post-key depth {depth}");
        }
    }
}

#[test]
fn nested_messages_share_the_recursion_budget() {
    let pre = cpace();
    let post = post_key();
    for depth in [0, 1, 98, 99, 100, 101, 102] {
        let pre_body = groups_then(&pre.step1().write_to_bytes().unwrap(), depth);
        let post_body = groups_then(&post.audio_frame().write_to_bytes().unwrap(), depth);
        let pre_result = Cpace::parse_from_bytes(&field(1, pre_body.len() as u64, &pre_body));
        let post_result = Message::parse_from_bytes(&field(11, post_body.len() as u64, &post_body));
        if depth <= 100 {
            assert_eq!(pre_result.unwrap(), pre, "pre-key nested depth {depth}");
            assert_eq!(post_result.unwrap(), post, "post-key nested depth {depth}");
        } else {
            assert!(pre_result.is_err(), "pre-key nested depth {depth}");
            assert!(post_result.is_err(), "post-key nested depth {depth}");
        }
    }
}

#[test]
fn declared_lengths_cannot_exceed_available_bytes() {
    for declared in [1, 127, 128, 4096, u32::MAX as u64, u64::MAX] {
        let unknown = field(100, declared, &[]);
        reject_length::<Cpace>(&unknown);
        reject_length::<Message>(&unknown);
        reject_length::<Cpace>(&field(1, declared, &[]));
        reject_length::<Message>(&field(11, declared, &[]));
        let nested = field(1, declared, &[]);
        reject_length::<Cpace>(&field(1, nested.len() as u64, &nested));
        reject_length::<Message>(&field(11, nested.len() as u64, &nested));
    }
    for length in [1, 127, 128, 1024] {
        let bytes = field(100, length, &vec![0x55; length as usize]);
        // Unknown fields with complete payloads are valid protobuf. The handshake
        // must separately require its expected step and exact field contents.
        assert!(Cpace::parse_from_bytes(&bytes).is_ok());
        assert!(Message::parse_from_bytes(&bytes).is_ok());
        for missing in [1, length] {
            let truncated = &bytes[..bytes.len() - missing as usize];
            assert!(Cpace::parse_from_bytes(truncated).is_err());
            assert!(Message::parse_from_bytes(truncated).is_err());
        }
    }
}

struct OneByteReader<'a>(&'a [u8]);

impl std::io::Read for OneByteReader<'_> {
    fn read(&mut self, target: &mut [u8]) -> std::io::Result<usize> {
        if target.is_empty() || self.0.is_empty() {
            return Ok(0);
        }
        target[0] = self.0[0];
        self.0 = &self.0[1..];
        Ok(1)
    }
}

fn input_sources<M: crate::protobuf::Message>(bytes: &[u8])
    -> [(&'static str, crate::protobuf::Result<M>); 4]
{
    let mut reader = std::io::BufReader::with_capacity(2, OneByteReader(bytes));
    let mut input = crate::protobuf::CodedInputStream::from_buf_read(&mut reader);
    let buffered = M::parse_from(&mut input).and_then(|message| {
        input.check_eof()?;
        Ok(message)
    });
    [
        ("slice", M::parse_from_bytes(bytes)),
        ("shared", M::parse_from_tokio_bytes(&bytes::Bytes::copy_from_slice(bytes))),
        ("reader", M::parse_from_reader(&mut OneByteReader(bytes))),
        ("buffered", buffered),
    ]
}

fn check_length_regions<M: crate::protobuf::Message>(
    tag: u64, body: &[u8], failures: &mut Vec<String>,
) {
    for valid in [Vec::new(), field(tag, 0, &[]), field(tag, body.len() as u64, body)] {
        let expected = M::parse_from_bytes(&valid).unwrap();
        for (source, result) in input_sources::<M>(&valid) {
            assert!(result.unwrap() == expected, "{} {source}: valid bytes differ", M::NAME);
        }
    }
    let mut refused = 0;
    for invalid in [field(tag, 1, &[]), field(tag, body.len() as u64 + 1, body)] {
        for (source, result) in input_sources::<M>(&invalid) {
            if result.is_err() {
                refused += 1;
            } else {
                failures.push(format!("{} {source} accepted {invalid:02x?}", M::NAME));
            }
        }
    }
    println!("PROTOBUF_LENGTH_INPUT type={} sources=4 valid=12 refused={refused}/8", M::NAME);
}

#[test]
fn truncated_length_regions_fail_for_all_input_sources() {
    let mut failures = Vec::new();
    check_length_regions::<Cpace>(1, &[0x0a, 0x01, 0x41], &mut failures);
    check_length_regions::<Message>(11, &[0x0a, 0x01, 0x41], &mut failures);
    check_length_regions::<CaptureDisplays>(1, &[0x01], &mut failures);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn malformed_wire_values_return_errors() {
    let mut cases = vec![vec![0x00], vec![0xa6, 0x06], vec![0xa7, 0x06]];
    for bytes in 1..=11 {
        let mut input = vec![0xa0, 0x06];
        input.extend(vec![0x80; bytes]);
        cases.push(input);
    }
    let mut overflow = vec![0xa0, 0x06];
    overflow.extend_from_slice(&[0xff; 9]);
    overflow.push(0x02);
    cases.push(overflow);
    for (tag, width) in [(0xa1, 8), (0xa5, 4)] {
        for length in 0..width {
            let mut input = vec![tag, 0x06];
            input.extend(vec![0x55; length]);
            cases.push(input);
        }
    }
    for bytes in cases {
        assert!(Cpace::parse_from_bytes(&bytes).is_err(), "pre-key {bytes:02x?}");
        assert!(Message::parse_from_bytes(&bytes).is_err(), "post-key {bytes:02x?}");
    }
}
