use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::package_format::{
    COMPOUND_FILE_HEADER, INSTALLER_MSI_NAME, MAGIC, MAX_MSI_SIZE, MD5_LENGTH, MSI_PATH,
};

#[cfg(windows)]
const BIN_DATA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/data.bin"));
const BUF_SIZE: usize = 4096;

pub(crate) struct InstallerPackage<'a> {
    compressed: &'a [u8],
    md5: &'a [u8],
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
    let value = (*input)
        .get(..length)
        .ok_or_else(|| "truncated embedded installer package".to_owned())?;
    *input = &input[length..];
    Ok(value)
}

fn read_length(input: &mut &[u8]) -> Result<usize, String> {
    let bytes = take(input, 4)?
        .try_into()
        .map_err(|_| "invalid embedded installer length".to_owned())?;
    usize::try_from(u32::from_be_bytes(bytes))
        .map_err(|_| "embedded installer length is not representable".to_owned())
}

fn require_bytes(input: &mut &[u8], expected: &[u8]) -> Result<(), String> {
    if take(input, expected.len())? != expected {
        return Err("invalid embedded installer package".to_owned());
    }
    Ok(())
}

fn decompress(compressed: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    use brotli::{reader::StandardAlloc, BrotliDecompressStream, BrotliResult, BrotliState};

    let mut state = BrotliState::new(
        StandardAlloc::default(),
        StandardAlloc::default(),
        StandardAlloc::default(),
    );
    let mut available_in = compressed.len();
    let mut input_offset = 0;
    let mut total_out = 0;
    let mut content = Vec::new();
    loop {
        let previous = (input_offset, total_out);
        let remaining = limit - content.len();
        let mut output = [0; BUF_SIZE];
        let mut available_out = BUF_SIZE.min(remaining.saturating_add(1));
        let mut output_offset = 0;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            compressed,
            &mut available_out,
            &mut output_offset,
            &mut output,
            &mut total_out,
            &mut state,
        );
        if output_offset > remaining {
            return Err("embedded installer exceeds its decompressed size limit".to_owned());
        }
        let needed = content.len() + output_offset;
        if needed > content.capacity() {
            let capacity = content.capacity().saturating_mul(2).max(needed).min(limit);
            content
                .try_reserve_exact(capacity - content.len())
                .map_err(|_| "cannot reserve embedded installer output".to_owned())?;
        }
        content.extend_from_slice(&output[..output_offset]);
        match result {
            BrotliResult::ResultSuccess => {
                if available_in != 0 || input_offset != compressed.len() {
                    return Err("trailing compressed installer data".to_owned());
                }
                return Ok(content);
            }
            BrotliResult::NeedsMoreOutput if previous != (input_offset, total_out) => {}
            _ => return Err("invalid or truncated compressed installer".to_owned()),
        }
    }
}

impl<'a> InstallerPackage<'a> {
    #[cfg(windows)]
    pub(crate) fn embedded() -> Result<Self, String> {
        Self::read_from(BIN_DATA)
    }

    pub(crate) fn read_from(mut input: &'a [u8]) -> Result<Self, String> {
        require_bytes(&mut input, MAGIC)?;
        if read_length(&mut input)? != MSI_PATH.len() {
            return Err("embedded installer must contain the fixed MSI path".to_owned());
        }
        require_bytes(&mut input, MSI_PATH)?;
        let length = read_length(&mut input)?;
        if length == 0 {
            return Err("empty compressed installer".to_owned());
        }
        let compressed = take(&mut input, length)?;
        let md5 = take(&mut input, MD5_LENGTH)?;
        if !md5.iter().all(|&byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')) {
            return Err("invalid embedded installer checksum".to_owned());
        }
        require_bytes(&mut input, MAGIC)?;
        require_bytes(&mut input, MSI_PATH)?;
        if !input.is_empty() {
            return Err("trailing embedded installer data".to_owned());
        }
        Ok(Self { compressed, md5 })
    }

    pub(crate) fn write_to_new_file(&self, prefix: &Path) -> Result<PathBuf, String> {
        let content = decompress(self.compressed, MAX_MSI_SIZE as usize)?;
        if !content.starts_with(COMPOUND_FILE_HEADER)
            || format!("{:x}", md5::compute(&content)).as_bytes() != self.md5
        {
            return Err("embedded installer content or checksum differs".to_owned());
        }
        let path = prefix.join(INSTALLER_MSI_NAME);
        fs::create_dir_all(prefix)
            .map_err(|err| format!("failed to create {}: {err}", prefix.display()))?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
        file.write_all(&content)
            .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
        file.sync_all()
            .map_err(|err| format!("failed to sync {}: {err}", path.display()))?;
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Read,
        sync::atomic::{AtomicU64, Ordering},
    };

    fn content() -> Vec<u8> {
        [COMPOUND_FILE_HEADER, b"fixture MSI bytes"].concat()
    }

    fn compressed(content: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        brotli::CompressorReader::new(content, BUF_SIZE, 11, 22)
            .read_to_end(&mut output)
            .unwrap();
        output
    }

    fn envelope(raw: &[u8], content: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(&(MSI_PATH.len() as u32).to_be_bytes());
        output.extend_from_slice(MSI_PATH);
        output.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        output.extend_from_slice(raw);
        output.extend_from_slice(format!("{:x}", md5::compute(content)).as_bytes());
        output.extend_from_slice(MAGIC);
        output.extend_from_slice(MSI_PATH);
        output
    }

    #[test]
    fn truncated_packages_return_errors() {
        let content = content();
        let encoded = envelope(&compressed(&content), &content);
        for length in 0..encoded.len() {
            assert!(InstallerPackage::read_from(&encoded[..length]).is_err(), "accepted {length}");
        }
        assert!(InstallerPackage::read_from(&encoded).is_ok());
    }

    #[test]
    fn package_envelope_is_exact() {
        let content = content();
        let encoded = envelope(&compressed(&content), &content);
        let length_offset = MAGIC.len() + 4 + MSI_PATH.len();
        let checksum_offset = encoded.len() - MSI_PATH.len() - MAGIC.len() - MD5_LENGTH;
        let mut invalid = Vec::new();
        for (offset, value) in [
            (0, 0),
            (MAGIC.len() + 4, 0xff),
            (checksum_offset, b'G'),
            (checksum_offset + MD5_LENGTH, 0),
            (encoded.len() - 1, b'x'),
        ] {
            let mut bytes = encoded.clone();
            bytes[offset] = value;
            invalid.push(bytes);
        }
        for offset in [MAGIC.len(), length_offset] {
            for value in [0u32, u32::MAX] {
                let mut bytes = encoded.clone();
                bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
                invalid.push(bytes);
            }
        }
        invalid.push([encoded.as_slice(), &[0]].concat());
        invalid.push([encoded.as_slice(), encoded.as_slice()].concat());
        for bytes in invalid {
            assert!(InstallerPackage::read_from(&bytes).is_err());
        }
    }

    #[test]
    fn decompression_is_bounded() {
        let content = [COMPOUND_FILE_HEADER, &vec![b'x'; 10000]].concat();
        let raw = compressed(&content);
        assert_eq!(decompress(&raw, content.len()).unwrap(), content);
        assert!(decompress(&raw, content.len() - 1).is_err());
        assert!(decompress(&raw, 0).is_err());
    }

    #[test]
    fn decompression_requires_complete_single_stream() {
        let content = content();
        let raw = compressed(&content);
        for length in 0..raw.len() {
            assert!(decompress(&raw[..length], content.len()).is_err());
        }
        assert!(decompress(&[raw.as_slice(), &[0]].concat(), content.len()).is_err());
        assert!(decompress(&[raw.as_slice(), raw.as_slice()].concat(), content.len() * 2).is_err());
        assert_eq!(decompress(&raw, content.len()).unwrap(), content);
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn invalid_payload_does_not_create_files() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let fixture = Fixture(std::env::temp_dir().join(format!(
            "installer-payload-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        )));
        fs::create_dir(&fixture.0).unwrap();
        let sentinel = fixture.0.join("sentinel");
        fs::write(&sentinel, b"sentinel").unwrap();
        let content = content();
        let valid = envelope(&compressed(&content), &content);
        let mut checksum_mismatch = valid.clone();
        let offset = valid.len() - MSI_PATH.len() - MAGIC.len() - MD5_LENGTH;
        checksum_mismatch[offset..offset + MD5_LENGTH].fill(b'0');
        for (index, bytes) in [
            checksum_mismatch,
            envelope(&compressed(b"not an MSI"), b"not an MSI"),
            envelope(&[0xff], &content),
            envelope(&[compressed(&content).as_slice(), &[0]].concat(), &content),
        ].iter().enumerate() {
            let package = InstallerPackage::read_from(bytes).unwrap();
            let destination = fixture.0.join(index.to_string());
            assert!(package.write_to_new_file(&destination).is_err());
            assert!(!destination.exists());
            assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        }
    }
}
