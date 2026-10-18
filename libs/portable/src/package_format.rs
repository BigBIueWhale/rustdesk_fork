pub(crate) const INSTALLER_MSI_NAME: &str = "rustdesk-installer.msi";
pub(crate) const MSI_PATH: &[u8] = b".\\rustdesk-installer.msi";
pub(crate) const MAGIC: &[u8] = b"rustdesk";
pub(crate) const MD5_LENGTH: usize = 32;
pub(crate) const MAX_MSI_SIZE: u64 = i32::MAX as u64;
pub(crate) const COMPOUND_FILE_HEADER: &[u8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
