use std::{
    collections::VecDeque,
    ffi::{OsStr, OsString},
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
};

enum Step {
    Root,
    Current,
    Parent,
    Name(OsString),
}

fn steps(path: &Path) -> Option<VecDeque<Step>> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.contains(&0) {
        return None;
    }
    let mut result = VecDeque::new();
    if path.is_absolute() {
        result.push_back(Step::Root);
    }
    for name in bytes.split(|&byte| byte == b'/').filter(|name| !name.is_empty()) {
        result.push_back(match name {
            b"." => Step::Current,
            b".." => Step::Parent,
            name => Step::Name(OsStr::from_bytes(name).to_owned()),
        });
    }
    // A trailing slash requires a directory, including inside a symlink's target.
    if bytes.last() == Some(&b'/') {
        result.push_back(Step::Current);
    }
    Some(result)
}

/// Resolve a fixed system executable through a namespace protected from non-root writers.
/// Callers retain responsibility for their finite candidate set, arguments and action authority.
pub fn resolve(path: &Path) -> Option<PathBuf> {
    let mut pending = steps(path)?;
    if !path.is_absolute()
        || pending.iter().any(|step| matches!(step, Step::Current | Step::Parent))
    {
        return None;
    }
    let root = fs::symlink_metadata("/").ok()?;
    if !root.is_dir() || root.uid() != 0 || root.mode() & 0o022 != 0 {
        return None;
    }
    let mut resolved = PathBuf::from("/");
    let mut symlinks = 0;
    while let Some(step) = pending.pop_front() {
        let name = match step {
            Step::Root => {
                resolved = PathBuf::from("/");
                continue;
            }
            Step::Current => continue,
            Step::Parent => {
                resolved.pop();
                continue;
            }
            Step::Name(name) => name,
        };
        let next = resolved.join(name);
        let metadata = fs::symlink_metadata(&next).ok()?;
        if metadata.uid() != 0 {
            return None;
        }
        if metadata.file_type().is_symlink() {
            if symlinks == 40 {
                return None;
            }
            symlinks += 1;
            // Resolve the target here: canonicalize alone hides intermediate writable paths.
            let target = fs::read_link(&next).ok()?;
            let mut target = steps(&target)?;
            target.append(&mut pending);
            pending = target;
        } else if metadata.is_dir() && metadata.mode() & 0o022 == 0 {
            if pending.is_empty() {
                return None;
            }
            resolved = next;
        } else if metadata.is_file()
            && pending.is_empty()
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0
        {
            return Some(next);
        } else {
            return None;
        }
    }
    None
}
