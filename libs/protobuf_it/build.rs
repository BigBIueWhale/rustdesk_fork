mod production {
    include!("../hbb_common/build.rs");

    pub fn generate() {
        main();
    }
}

fn main() -> std::io::Result<()> {
    std::env::set_current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../hbb_common"))?;
    production::generate();
    Ok(())
}
