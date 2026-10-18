use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

use crate::package_format::{COMPOUND_FILE_HEADER, MAGIC, MAX_MSI_SIZE, MSI_PATH};

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

pub(crate) fn generate(path: &Path, output_dir: &Path) -> io::Result<()> {
    let mut data = File::create(output_dir.join("data.bin"))?;
    write_package(path, &mut data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bin_reader::InstallerPackage;
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
        let package = InstallerPackage::read_from(bytes).unwrap();
        let extracted = package.write_to_new_file(&fixture.0.join("extract")).unwrap();
        assert_eq!(extracted.file_name().unwrap(), "rustdesk-installer.msi");
        assert_eq!(fs::read(extracted).unwrap(), original);
    }

    #[test]
    fn generation_is_deterministic_and_overwrites_old_outputs() {
        let fixture = Fixture::new();
        let msi = fixture.msi();
        generate(&msi, &fixture.0).unwrap();
        let package = fs::read(fixture.0.join("data.bin")).unwrap();
        fs::write(fixture.0.join("data.bin"), "stale package").unwrap();
        generate(&msi, &fixture.0).unwrap();
        assert_eq!(fs::read(fixture.0.join("data.bin")).unwrap(), package);
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
    fn extraction_refuses_existing_file_without_modification() {
        let fixture = Fixture::new();
        let mut package = Cursor::new(Vec::new());
        write_package(&fixture.msi(), &mut package).unwrap();
        let package = InstallerPackage::read_from(Box::leak(package.into_inner().into_boxed_slice())).unwrap();
        let destination = fixture.0.join("rustdesk-installer.msi");
        fs::write(&destination, "existing").unwrap();
        assert!(package.write_to_new_file(&fixture.0).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"existing");
        fs::remove_file(&destination).unwrap();
        package.write_to_new_file(&fixture.0).unwrap();
        let original = fs::read(&destination).unwrap();
        assert!(package.write_to_new_file(&fixture.0).is_err());
        assert_eq!(fs::read(&destination).unwrap(), original);
    }

    #[cfg(unix)]
    #[test]
    fn extraction_refuses_symlink_and_hard_link_targets() {
        let fixture = Fixture::new();
        let mut package = Cursor::new(Vec::new());
        write_package(&fixture.msi(), &mut package).unwrap();
        let package = InstallerPackage::read_from(Box::leak(package.into_inner().into_boxed_slice())).unwrap();
        let sentinel = fixture.0.join("sentinel");
        let destination = fixture.0.join("rustdesk-installer.msi");
        fs::write(&sentinel, "sentinel").unwrap();
        std::os::unix::fs::symlink(&sentinel, &destination).unwrap();
        assert!(package.write_to_new_file(&fixture.0).is_err());
        assert!(fs::symlink_metadata(&destination).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        fs::remove_file(&destination).unwrap();
        fs::hard_link(&sentinel, &destination).unwrap();
        assert!(package.write_to_new_file(&fixture.0).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"sentinel");
        assert_eq!(fs::read(&destination).unwrap(), b"sentinel");
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
