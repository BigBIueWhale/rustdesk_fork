use std::path::{Path, PathBuf};

// Observe staging established by a live production receive job. Never invent
// an absent namespace when an assertion intends to inspect owned artifacts.
pub(crate) fn artifact_paths(destination: &Path, name: &str) -> [PathBuf; 3] {
    #[cfg(target_os = "linux")]
    {
        use hbb_common::{libc, sha2::{Digest, Sha256}};
        use std::os::unix::fs::MetadataExt;

        let namespaces: Vec<_> = std::fs::read_dir(destination).unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| entry.file_name().as_encoded_bytes().starts_with(b".rustdesk-receive-"))
            .map(|entry| entry.path()).collect();
        assert_eq!(namespaces.len(), 1, "expected one admitted receive namespace");
        let metadata = std::fs::symlink_metadata(&namespaces[0]).unwrap();
        assert!(metadata.is_dir());
        assert_eq!((metadata.uid(), metadata.mode() & 0o7777),
            (unsafe { libc::geteuid() }, 0o700));
        let mut hash = Sha256::new();
        hash.update(b"rustdesk.receive.file.v1\0");
        hash.update(name.as_bytes());
        let directory = namespaces[0].join(format!("{:x}", hash.finalize()));
        ["payload.download", "resume.digest", "claim.download.lock"]
            .map(|name| directory.join(name))
    }
    #[cfg(not(target_os = "linux"))]
    {
        [".download", ".digest", ".download.lock"]
            .map(|suffix| destination.join(format!("{name}{suffix}")))
    }
}

pub(crate) fn prepare_artifact_paths(destination: &Path, name: &str) -> [PathBuf; 3] {
    let paths = artifact_paths(destination, name);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(paths[0].parent().unwrap()).unwrap();
    }
    paths
}
