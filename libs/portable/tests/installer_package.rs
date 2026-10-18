#[path = "../src/bin_reader.rs"]
mod bin_reader;
#[path = "../src/installer_package.rs"]
mod installer_package;

use bin_reader::BinaryReader as InstallerPackage;
#[path = "support/decoder_no_panic.rs"]
mod decoder_no_panic;
