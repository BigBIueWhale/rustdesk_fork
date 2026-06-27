pub fn worker_arg() -> &'static str {
    clipboard::platform::unix::file_descriptor_worker_arg()
}

pub fn run_worker() -> hbb_common::ResultType<()> {
    clipboard::platform::unix::run_file_descriptor_worker()?;
    Ok(())
}
