use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const MSI_PATH: &[u8] = b".\\rustdesk-installer.msi";
const MAGIC: &[u8] = b"rustdesk";
const MAX_MSI_SIZE: u64 = i32::MAX as u64;
const COMPOUND_FILE_HEADER: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn regular(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    metadata.is_file() && !metadata.file_type().is_symlink()
}

fn same_file(before: &Metadata, after: &Metadata) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Ok(false);
        }
    }
    Ok(regular(after)
        && before.len() == after.len()
        && before.modified()? == after.modified()?)
}

fn read_msi(path: &Path) -> io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !regular(&before) || before.len() == 0 || before.len() > MAX_MSI_SIZE {
        return Err(invalid(
            "installer MSI must be a nonempty regular file smaller than 2 GiB",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_SHARE_READ only; retain the source without write/delete sharing.
        // FILE_FLAG_OPEN_REPARSE_POINT opens the final entry for handle validation.
        options.share_mode(1).custom_flags(0x00200000);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !same_file(&before, &opened)? {
        return Err(invalid("installer MSI changed before read"));
    }
    let capacity = usize::try_from(opened.len())
        .map_err(|_| invalid("installer MSI size is not representable"))?;
    let mut content = Vec::new();
    content
        .try_reserve_exact(capacity)
        .map_err(|_| invalid("cannot reserve installer MSI snapshot"))?;
    (&file).take(opened.len() + 1).read_to_end(&mut content)?;
    if content.len() != capacity
        || !same_file(&opened, &file.metadata()?)?
        || !same_file(&opened, &fs::symlink_metadata(path)?)?
    {
        return Err(invalid("installer MSI changed during read"));
    }
    if !content.starts_with(COMPOUND_FILE_HEADER) {
        return Err(invalid("installer MSI lacks its compound-file header"));
    }
    Ok(content)
}

pub(crate) fn app_metadata(epoch: &str) -> io::Result<String> {
    if epoch.is_empty()
        || !epoch.bytes().all(|byte| byte.is_ascii_digit())
        || (epoch.len() > 1 && epoch.starts_with('0'))
    {
        return Err(invalid(
            "SOURCE_DATE_EPOCH must be canonical unsigned decimal seconds",
        ));
    }
    let milliseconds = epoch
        .parse::<u64>()
        .ok()
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or_else(|| invalid("SOURCE_DATE_EPOCH milliseconds overflow"))?;
    Ok(format!("timestamp = {milliseconds}\n"))
}

pub(crate) fn write_package(path: &Path, output: &mut (impl Write + Seek)) -> io::Result<()> {
    let content = read_msi(path)?;
    output.write_all(MAGIC)?;
    output.write_all(&(MSI_PATH.len() as u32).to_be_bytes())?;
    output.write_all(MSI_PATH)?;
    let length_offset = output.stream_position()?;
    output.write_all(&0u32.to_be_bytes())?;
    let data_offset = output.stream_position()?;
    let mut compressor = brotli::CompressorReader::new(content.as_slice(), 4096, 11, 22);
    let compressed_length = io::copy(&mut compressor, output)?;
    let compressed_length = u32::try_from(compressed_length)
        .map_err(|_| invalid("compressed MSI length exceeds package format"))?;
    output.seek(SeekFrom::Start(length_offset))?;
    output.write_all(&compressed_length.to_be_bytes())?;
    output.seek(SeekFrom::Start(data_offset + u64::from(compressed_length)))?;
    output.write_all(format!("{:x}", md5::compute(&content)).as_bytes())?;
    output.write_all(MAGIC)?;
    output.write_all(MSI_PATH)?;
    output.flush()
}

pub(crate) fn generate(path: &Path, output_dir: &Path, epoch: &str) -> io::Result<()> {
    let metadata = app_metadata(epoch)?;
    let mut data = File::create(output_dir.join("data.bin"))?;
    write_package(path, &mut data)?;
    fs::write(output_dir.join("app_metadata.toml"), metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_reader::BinaryReader;
    use std::{
        io::Cursor,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "installer-package-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn msi(&self) -> PathBuf {
            let path = self.0.join("input.msi");
            fs::write(&path, [COMPOUND_FILE_HEADER, b"fixture MSI bytes\0\xff"].concat()).unwrap();
            path
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn package_round_trips_through_installer_decoder() {
        let fixture = Fixture::new();
        let msi = fixture.msi();
        let original = fs::read(&msi).unwrap();
        let mut package = Cursor::new(Vec::new());
        write_package(&msi, &mut package).unwrap();
        let bytes = Box::leak(package.into_inner().into_boxed_slice());
        let (files, startup) = BinaryReader::read_from(bytes);
        assert_eq!(files.len(), 1);
        assert_eq!(startup, String::from_utf8(MSI_PATH.to_vec()).unwrap());
        assert_eq!(files[0].path, startup);
        assert_eq!(
            files[0].md5_code,
            format!("{:x}", md5::compute(&original)).as_bytes()
        );
        let extracted = files[0].write_to_file(&fixture.0.join("extract")).unwrap();
        assert_eq!(extracted.file_name().unwrap(), "rustdesk-installer.msi");
        assert_eq!(fs::read(extracted).unwrap(), original);
    }

    #[test]
    fn generation_is_deterministic_and_overwrites_old_outputs() {
        let fixture = Fixture::new();
        let msi = fixture.msi();
        generate(&msi, &fixture.0, "1720000000").unwrap();
        let package = fs::read(fixture.0.join("data.bin")).unwrap();
        fs::write(fixture.0.join("app_metadata.toml"), "stale wall clock").unwrap();
        generate(&msi, &fixture.0, "1720000000").unwrap();
        assert_eq!(fs::read(fixture.0.join("data.bin")).unwrap(), package);
        assert_eq!(
            fs::read(fixture.0.join("app_metadata.toml")).unwrap(),
            b"timestamp = 1720000000000\n"
        );
    }

    #[test]
    fn epoch_is_required_canonical_and_bounded() {
        assert_eq!(app_metadata("0").unwrap(), "timestamp = 0\n");
        assert_eq!(
            app_metadata("18446744073709551").unwrap(),
            "timestamp = 18446744073709551000\n"
        );
        for value in [
            "", "01", "-1", "+1", "1.0", "1\n", " 1",
            "18446744073709552", "18446744073709551616",
        ] {
            assert!(app_metadata(value).is_err(), "accepted {value:?}");
        }
        let fixture = Fixture::new();
        assert!(generate(&fixture.msi(), &fixture.0, "").is_err());
        assert!(!fixture.0.join("data.bin").exists());
    }

    #[test]
    fn input_refuses_missing_empty_non_msi_and_oversized_files() {
        let fixture = Fixture::new();
        let path = fixture.0.join("input.msi");
        let mut output = Cursor::new(Vec::new());
        assert!(write_package(&path, &mut output).is_err());
        fs::write(&path, []).unwrap();
        assert!(write_package(&path, &mut output).is_err());
        fs::write(&path, "not an MSI").unwrap();
        assert!(write_package(&path, &mut output).is_err());
        File::create(&path).unwrap().set_len(MAX_MSI_SIZE + 1).unwrap();
        assert!(write_package(&path, &mut output).is_err());
        assert!(output.into_inner().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn input_refuses_symlink_without_reading_target() {
        let fixture = Fixture::new();
        let path = fixture.0.join("linked.msi");
        std::os::unix::fs::symlink(fixture.msi(), &path).unwrap();
        assert!(write_package(&path, &mut Cursor::new(Vec::new())).is_err());
    }

    #[test]
    fn compression_and_length_patch_failures_are_returned() {
        struct FailingOutput {
            inner: Cursor<Vec<u8>>,
            fail_seek: bool,
        }
        impl Write for FailingOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if !self.fail_seek
                    && self.inner.position() >= (MAGIC.len() + 4 + MSI_PATH.len() + 4) as u64
                {
                    return Err(io::Error::new(io::ErrorKind::Other, "fixture write failure"));
                }
                self.inner.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        impl Seek for FailingOutput {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                if self.fail_seek && matches!(position, SeekFrom::Start(_)) {
                    return Err(io::Error::new(io::ErrorKind::Other, "fixture seek failure"));
                }
                self.inner.seek(position)
            }
        }
        let fixture = Fixture::new();
        let msi = fixture.msi();
        for fail_seek in [false, true] {
            let mut output = FailingOutput {
                inner: Cursor::new(Vec::new()),
                fail_seek,
            };
            let error = write_package(&msi, &mut output).unwrap_err();
            assert_eq!(
                error.to_string(),
                if fail_seek { "fixture seek failure" } else { "fixture write failure" }
            );
        }
    }
}
