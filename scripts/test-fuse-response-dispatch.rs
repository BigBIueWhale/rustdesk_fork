use crate::clipboard::ClipboardSide;
use ::clipboard::{platform::unix::fuse, ClipboardFile};
use hbb_common::config::APP_NAME;
use std::{fs::OpenOptions, io::Write, path::Path, process::Command};

fn scenario(case: &str, test_name: &str) {
    if let Ok(child_case) = std::env::var("RD_FUSE_DISPATCH_CASE") {
        assert_eq!(child_case, case);
        observe(case);
        return;
    }
    for implementation in ["before", "current"] {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name, "--nocapture"])
            .env("RD_FUSE_DISPATCH_CASE", case)
            .env("RD_FUSE_DISPATCH_IMPLEMENTATION", implementation)
            .output()
            .unwrap();
        assert!(output.status.success(), "{case}/{implementation}: {}{}",
                String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert_eq!(stdout.matches("FUSE_DISPATCH_OBSERVATION=").count(), 1);
        for line in stdout.lines().filter(|line| line.starts_with("FUSE_DISPATCH_OBSERVATION=")) {
            let path = std::env::var_os("RD_FUSE_DISPATCH_OBSERVATIONS").unwrap();
            let mut record = OpenOptions::new().append(true).open(path).unwrap();
            writeln!(record, "{line}").unwrap();
        }
    }
}

fn observe(case: &str) {
    assert!(!Path::new("/dev/fuse").exists(), "probe requires no FUSE device");
    assert!(!fuse::is_fuse_context_inited(true));
    assert!(!fuse::is_fuse_context_inited(false));
    let implementation = std::env::var("RD_FUSE_DISPATCH_IMPLEMENTATION").unwrap();
    assert!(implementation == "before" || implementation == "current");
    let is_client = case.ends_with("client");
    let is_format = case.contains("format-");
    let failed_format = case.starts_with("failed-format-");
    let side = if is_client { ClipboardSide::Client } else { ClipboardSide::Host };
    let app = format!("rustdesk-fuse-dispatch-{}", std::process::id());
    *APP_NAME.write().unwrap() = app.clone();
    let root = Path::new("/tmp").join(&app);
    assert!(!root.exists(), "probe namespace already exists");
    let clip = if is_format {
        ClipboardFile::FormatDataResponse {
            msg_flags: if failed_format { 2 } else { 1 }, format_data: vec![0],
        }
    } else {
        ClipboardFile::FileContentsResponse { msg_flags: 1, stream_id: 7, requested_data: vec![1] }
    };
    let replies = if implementation == "before" {
        crate::before::unix_file_clip::serve_clip_messages(side, clip, 17)
    } else {
        crate::clipboard_file::unix_file_clip::serve_clip_messages(side, clip, 17)
    };
    assert!(replies.is_empty());
    let client = root.join("cliprdr-client").is_dir();
    let host = root.join("cliprdr-server").is_dir();
    if implementation == "before" {
        assert!(client && !host, "old dispatcher did not expose its client-context bootstrap");
    } else if is_format && !failed_format {
        assert_eq!((client, host), (is_client, !is_client), "wrong bootstrap side");
    } else {
        assert!(!client && !host && !root.exists(), "content reply created a FUSE namespace");
    }
    assert!(!fuse::is_fuse_context_inited(true));
    assert!(!fuse::is_fuse_context_inited(false));
    for name in ["cliprdr-client", "cliprdr-server"] {
        let path = root.join(name);
        if path.exists() { std::fs::remove_dir(path).unwrap(); }
    }
    if root.exists() { std::fs::remove_dir(&root).unwrap(); }
    assert!(!root.exists());
    println!("FUSE_DISPATCH_OBSERVATION=case={case} implementation={implementation} client_dir={client} host_dir={host} context=absent cleanup=removed");
}

#[test]
fn content_reply_preserves_absent_contexts() {
    if let Ok(case) = std::env::var("RD_FUSE_DISPATCH_CASE") {
        assert!(case == "reply-client" || case == "reply-host");
        observe(&case);
        return;
    }
    for case in ["reply-client", "reply-host"] {
        scenario(case, "dispatch_tests::content_reply_preserves_absent_contexts");
    }
}

#[test]
fn host_format_reply_selects_host_context() {
    scenario("format-host", "dispatch_tests::host_format_reply_selects_host_context");
}

#[test]
fn client_format_reply_selects_client_context() {
    scenario("format-client", "dispatch_tests::client_format_reply_selects_client_context");
}

#[test]
fn failed_format_reply_preserves_absent_contexts() {
    if let Ok(case) = std::env::var("RD_FUSE_DISPATCH_CASE") {
        assert!(case == "failed-format-client" || case == "failed-format-host");
        observe(&case);
        return;
    }
    for case in ["failed-format-client", "failed-format-host"] {
        scenario(case, "dispatch_tests::failed_format_reply_preserves_absent_contexts");
    }
}
