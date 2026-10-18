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

    fn entries(path: &Path) -> std::collections::BTreeSet<std::ffi::OsString> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    #[test]
    fn generation_invalid_input_preserves_published_output() {
        let fixture = Fixture::new();
        let msi = fixture.0.join("input.msi");
        let output = fixture.0.join("data.bin");
        let mut preserved = true;
        for existing in [false, true] {
            for content in [None, Some(b"".as_slice()), Some(b"not an MSI".as_slice())] {
                if msi.exists() {
                    fs::remove_file(&msi).unwrap();
                }
                if let Some(content) = content {
                    fs::write(&msi, content).unwrap();
                }
                if output.exists() {
                    fs::remove_file(&output).unwrap();
                }
                if existing {
                    fs::write(&output, b"previous published package").unwrap();
                }
                let before = entries(&fixture.0);
                assert!(generate(&msi, &fixture.0).is_err());
                preserved &= entries(&fixture.0) == before;
                preserved &= if existing {
                    fs::read(&output).unwrap() == b"previous published package"
                } else {
                    !output.exists()
                };
            }
        }
        println!("INSTALLER_GENERATION_INVALID=observed cases=6 output_preserved={}", preserved);
        assert!(preserved);
    }

    #[cfg(unix)]
    #[test]
    fn generation_replaces_output_without_mutating_existing_aliases() {
        let fixture = Fixture::new();
        let msi = fixture.msi();
        let original = fs::read(&msi).unwrap();
        let output = fixture.0.join("data.bin");
        let alias = fixture.0.join("old-package-alias");
        let previous = b"previous published package";
        fs::write(&output, previous).unwrap();
        fs::hard_link(&output, &alias).unwrap();
        let mut reader = File::open(&output).unwrap();
        let before = entries(&fixture.0);
        generate(&msi, &fixture.0).unwrap();
        let hard_link_preserved = fs::read(&alias).unwrap() == previous;
        let mut retained = Vec::new();
        reader.read_to_end(&mut retained).unwrap();
        let reader_preserved = retained == previous;
        let mut no_temporary_left = entries(&fixture.0) == before;
        let encoded = fs::read(&output).unwrap();
        let package = InstallerPackage::read_from(&encoded).unwrap();
        let extracted = package.write_to_new_file(&fixture.0.join("hard-link-extract")).unwrap();
        assert_eq!(fs::read(extracted).unwrap(), original);

        fs::remove_file(&output).unwrap();
        std::os::unix::fs::symlink(&msi, &output).unwrap();
        let before = entries(&fixture.0);
        let result = generate(&msi, &fixture.0);
        let target_preserved = fs::read(&msi).unwrap() == original;
        let mut symlink_replaced = false;
        if result.is_ok() {
            let metadata = fs::symlink_metadata(&output).unwrap();
            symlink_replaced = metadata.is_file() && !metadata.file_type().is_symlink();
            let encoded = fs::read(&output).unwrap();
            let package = InstallerPackage::read_from(&encoded).unwrap();
            let extracted = package.write_to_new_file(&fixture.0.join("symlink-extract")).unwrap();
            assert_eq!(fs::read(extracted).unwrap(), original);
            let mut expected = before;
            expected.insert("symlink-extract".into());
            no_temporary_left &= entries(&fixture.0) == expected;
        } else {
            no_temporary_left &= entries(&fixture.0) == before;
        }
        println!(
            "INSTALLER_GENERATION_ALIASES=observed hard_link_preserved={} reader_preserved={} target_preserved={} symlink_replaced={} temporary_retired={}",
            hard_link_preserved, reader_preserved, target_preserved, symlink_replaced, no_temporary_left,
        );
        assert!(hard_link_preserved && reader_preserved && target_preserved
            && symlink_replaced && no_temporary_left);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn generation_write_failure_preserves_output_and_retires_owned_temp() {
        const CHILD: &str = "RUSTDESK_INSTALLER_FSIZE_TEST_CHILD";
        if let Some(directory) = std::env::var_os(CHILD) {
            let directory = PathBuf::from(directory);
            fn written_bytes() -> u64 {
                fs::read_to_string("/proc/self/io").unwrap().lines()
                    .find_map(|line| line.strip_prefix("wchar: "))
                    .unwrap().parse().unwrap()
            }
            // Only this disposable test child changes its signal disposition and file-size limit.
            unsafe {
                assert_ne!(libc::signal(libc::SIGXFSZ, libc::SIG_IGN), libc::SIG_ERR);
                let limit = libc::rlimit { rlim_cur: 8, rlim_max: 8 };
                assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
            }
            let before = written_bytes();
            let error = generate(&directory.join("input.msi"), &directory).unwrap_err();
            let written = written_bytes() - before;
            assert_eq!(error.raw_os_error(), Some(libc::EFBIG));
            assert_eq!(written, 8);
            println!("INSTALLER_GENERATION_NATIVE_WRITE=observed bytes=8 error=EFBIG");
            return;
        }
        let fixture = Fixture::new();
        let msi = fixture.msi();
        let original = fs::read(&msi).unwrap();
        let output = fixture.0.join("data.bin");
        fs::write(&output, b"previous published package").unwrap();
        let before = entries(&fixture.0);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "installer_package::tests::generation_write_failure_preserves_output_and_retires_owned_temp",
                "--nocapture", "--quiet"])
            .env(CHILD, &fixture.0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let started = std::time::Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if started.elapsed() > std::time::Duration::from_secs(3) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("native write-failure child exceeded its deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        let child_output = String::from_utf8(result.stdout).unwrap();
        assert!(child_output.contains("INSTALLER_GENERATION_NATIVE_WRITE=observed bytes=8 error=EFBIG"));
        let output_preserved = fs::read(&output).unwrap() == b"previous published package";
        let temporary_retired = entries(&fixture.0) == before;
        assert_eq!(fs::read(&msi).unwrap(), original);
        println!(
            "INSTALLER_GENERATION_FAILURE=observed native_written_bytes=8 error=EFBIG child_joined=true output_preserved={} temporary_retired={}",
            output_preserved, temporary_retired,
        );
        assert!(output_preserved && temporary_retired);
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
