use crate::{installer_package::write_package, InstallerPackage};
use std::{fs, io::Cursor, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn truncated_packages_do_not_panic() {
    let fixture = Fixture(std::env::temp_dir().join(format!("installer-decoder-{}", std::process::id())));
    fs::create_dir(&fixture.0).unwrap();
    let msi = fixture.0.join("input.msi");
    fs::write(&msi, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture MSI").unwrap();
    let mut package = Cursor::new(Vec::new());
    write_package(&msi, &mut package).unwrap();
    let package = package.into_inner();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let mut panics = Vec::new();
    for length in 0..package.len() {
        let input = Box::leak(package[..length].to_vec().into_boxed_slice());
        if std::panic::catch_unwind(|| {
            let _ = InstallerPackage::read_from(input);
        }).is_err() {
            panics.push(length);
        }
    }
    std::panic::set_hook(hook);
    println!("INSTALLER_DECODER_TRUNCATION=cases={} panics={}", package.len(), panics.len());
    assert!(panics.is_empty(), "decoder panicked at lengths {panics:?}");
}
