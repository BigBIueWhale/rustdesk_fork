//! Unicode 15.1 NFC conformance against independent published expectations.
//! The authenticated offline vendor closure already contains the complete corpus;
//! do not generate expected output with the normalizer's own Unicode tables.

use pake::nfc_normalize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const CORPUS_SHA256: &str = "871238e37e3be0696ec2bd0891119a041b052da1a84485eda05a5438724b223e";

struct Row {
    line: usize,
    part: usize,
    columns: [String; 5],
}

fn corpus() -> Vec<Row> {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (15, 1, 0));
    let path = std::env::var_os("NFC_CONFORMANCE_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../online/inputs/cargo-vendor/unicode-width-0.1.13/tests/NormalizationTest.txt")
        });
    let bytes = std::fs::read(path).expect("pinned offline Unicode conformance data");
    assert_eq!(bytes.len(), 2_625_136);
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), CORPUS_SHA256);
    let text = std::str::from_utf8(&bytes).expect("Unicode corpus UTF-8");
    assert!(text.starts_with("# NormalizationTest-15.1.0.txt\n"));
    let mut rows = Vec::new();
    let mut parts = 0;
    let mut counts = [0; 4];
    for (line, content) in text.lines().enumerate() {
        let content = content.split('#').next().unwrap().trim();
        if content.is_empty() {
            continue;
        }
        if content.starts_with('@') {
            assert_eq!(content, format!("@Part{parts}"));
            parts += 1;
            assert!(parts <= 4);
            continue;
        }
        assert!(parts > 0);
        let fields: Vec<_> = content.split(';').collect();
        assert_eq!(fields.len(), 6, "line {}", line + 1);
        assert!(fields[5].trim().is_empty());
        let columns = std::array::from_fn(|index| {
            let column: String = fields[index]
                .split_whitespace()
                .map(|hex| {
                    char::from_u32(u32::from_str_radix(hex, 16).expect("hex code point"))
                        .expect("Unicode scalar")
                })
                .collect();
            assert!(!column.is_empty());
            column
        });
        counts[parts - 1] += 1;
        rows.push(Row {
            line: line + 1,
            part: parts - 1,
            columns,
        });
    }
    assert_eq!(parts, 4);
    assert_eq!(counts, [25, 17_029, 1_844, 176]);
    assert_eq!(rows.len(), 19_074);
    rows
}

#[test]
fn unicode_15_1_official_nfc_rows() {
    let mut checks = 0;
    for row in corpus() {
        // UAX #15: c2 = NFC(c1) = NFC(c2) = NFC(c3),
        // and c4 = NFC(c4) = NFC(c5). This does not apply NFKC to passwords.
        for (index, input) in row.columns.iter().enumerate() {
            let expected = &row.columns[if index < 3 { 1 } else { 3 }];
            assert_eq!(
                &*nfc_normalize(input), expected.as_bytes(),
                "Unicode line {}, column {}", row.line, index + 1
            );
            checks += 1;
        }
    }
    assert_eq!(checks, 95_370);
    println!("NFC_CONFORMANCE_ROWS=pass unicode=15.1.0 rows=19074 checks={checks} corpus_sha256={CORPUS_SHA256}");
}

#[test]
fn unicode_15_1_unlisted_scalars_remain_unchanged() {
    let mut listed = vec![false; 0x11_0000];
    for row in corpus().into_iter().filter(|row| row.part == 1) {
        let mut source = row.columns[0].chars();
        let scalar = source.next().expect("Part 1 scalar") as usize;
        assert!(source.next().is_none());
        assert!(!listed[scalar], "duplicate Part 1 scalar");
        listed[scalar] = true;
    }
    let mut checks = 0;
    for value in 0..=0x10_ffff {
        if let Some(scalar) = char::from_u32(value) {
            if !listed[value as usize] {
                let mut buffer = [0; 4];
                let input = scalar.encode_utf8(&mut buffer);
                assert_eq!(&*nfc_normalize(input), input.as_bytes(), "U+{value:04X}");
                checks += 1;
            }
        }
    }
    // Includes unassigned values/noncharacters as well as the assigned scalars
    // required by the corpus. Surrogates are not valid Rust string scalars.
    assert_eq!(checks, 1_095_035);
    println!("NFC_CONFORMANCE_SCALARS=pass unicode=15.1.0 unchanged={checks} listed=17029");
}

#[test]
fn password_policy_preserves_case_spaces_and_compatibility() {
    for input in [
        "", "Password", "password", " password ", "\u{a0}", "\u{3000}",
        "\u{ff21}", "\u{fb03}", "\u{2163}", "\u{200d}", "\0", "\u{10ffff}",
    ] {
        assert_eq!(&*nfc_normalize(input), input.as_bytes());
    }
    println!("NFC_PASSWORD_POLICY=pass cases=12 scope=normalization-only casefold=absent compatibility-fold=absent space-mapping=absent");
}
