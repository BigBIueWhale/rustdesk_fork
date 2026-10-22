use crate::screenshot_png::BoundedScreenshotPng;
use crate::test_allocator::{arm, refusals};
use std::io::{self, Write};

struct RefusePngWrite<'a> {
    destination: &'a mut BoundedScreenshotPng,
    armed: bool,
}

impl Write for RefusePngWrite<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.armed {
            self.armed = false;
            arm();
        }
        self.destination.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.destination.flush()
    }
}

#[test]
fn allocation_refusal_preserves_png_bytes_and_reaches_encoder() {
    let mut destination = BoundedScreenshotPng::new();
    destination.write_all(b"prefix").unwrap();
    arm();
    assert_eq!(destination.write(&[]).unwrap(), 0);
    let error = destination.write(&[0x41; 128]).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    destination.write_all(b"_ok").unwrap();
    assert_eq!(destination.into_bytes(), b"prefix_ok");
    assert_eq!(refusals(), 1);

    let mut destination = BoundedScreenshotPng::new();
    {
        let mut writer = RefusePngWrite { destination: &mut destination, armed: true };
        let error = match repng::Options::smallest(129, 33).build(&mut writer) {
            Err(error) => error,
            Ok(_) => panic!("PNG encoder ignored allocation refusal"),
        };
        assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
    }
    assert!(destination.into_bytes().is_empty());
    assert_eq!(refusals(), 2);

    let mut limited = BoundedScreenshotPng::with_limit(4);
    limited.write_all(b"1234").unwrap();
    assert_eq!(limited.write(b"5").unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(limited.into_bytes(), b"1234");

    let mut rgba = Vec::new();
    for _ in 0..33 {
        for x in 0..129 {
            rgba.extend_from_slice(&match x {
                0..=31 => [255, 0, 0, 255],
                32..=63 => [0, 255, 0, 255],
                64..=95 => [0, 0, 255, 255],
                _ => [255, 255, 255, 255],
            });
        }
    }
    let mut png = BoundedScreenshotPng::new();
    let mut encoder = repng::Options::smallest(129, 33).build(&mut png).unwrap();
    encoder.write(&rgba).unwrap();
    encoder.finish().unwrap();
    drop(encoder);
    let png = png.into_bytes();
    let mut limited = BoundedScreenshotPng::with_limit(png.len() - 1);
    let limited_result = (|| -> io::Result<()> {
        let mut encoder = repng::Options::smallest(129, 33).build(&mut limited)?;
        encoder.write(&rgba)?;
        encoder.finish()?;
        Ok(())
    })();
    assert_eq!(limited_result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    let partial = limited.into_bytes();
    assert!(partial.len() < png.len() && png.starts_with(&partial));
    let mut hex = String::with_capacity(png.len() * 2);
    for byte in &png {
        use std::fmt::Write;
        write!(&mut hex, "{byte:02x}").unwrap();
    }
    println!("SCREENSHOT_PNG_BOUNDED_HEX={hex}");
    println!("SCREENSHOT_PNG_ALLOC_NATIVE=pass refusals=2 direct=OutOfMemory encoder=OutOfMemory prefix=preserved retry=pass byte_limit=preserved fresh_png_bytes={}", png.len());
}
