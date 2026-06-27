pub fn worker_arg() -> &'static str {
    clipboard::platform::unix::file_contents_worker_arg()
}

pub fn run_worker() -> hbb_common::ResultType<()> {
    clipboard::platform::unix::run_file_contents_worker()?;
    Ok(())
}
