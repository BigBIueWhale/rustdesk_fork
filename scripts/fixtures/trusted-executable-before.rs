// Exact shared production selector from b3f8206a; negative native control only.
use std::{path::{Component, Path, PathBuf}, os::unix::fs::MetadataExt};
fn linux_helper_path_is_clean_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}
fn trusted_command_file_metadata(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0
}
fn trusted_command_parent_metadata(is_dir: bool, uid: u32, mode: u32) -> bool {
    is_dir && uid == 0 && mode & 0o022 == 0
}
fn trusted_command_file(metadata: &std::fs::Metadata) -> bool {
    trusted_command_file_metadata(metadata.is_file(), metadata.uid(), metadata.mode())
}
fn trusted_command_parent(metadata: &std::fs::Metadata) -> bool {
    trusted_command_parent_metadata(metadata.is_dir(), metadata.uid(), metadata.mode())
}
fn trusted_fixed_executable_path(path: &Path) -> Option<PathBuf> {
    if !linux_helper_path_is_clean_absolute(path) {
        return None;
    }
    let candidate_parent = path.parent()?;
    if !trusted_command_parent(&std::fs::metadata(candidate_parent).ok()?) {
        return None;
    }
    let canonical = std::fs::canonicalize(path).ok()?;
    if !linux_helper_path_is_clean_absolute(&canonical) {
        return None;
    }
    let canonical_parent = canonical.parent()?;
    if !trusted_command_parent(&std::fs::metadata(canonical_parent).ok()?) {
        return None;
    }
    if !trusted_command_file(&std::fs::metadata(&canonical).ok()?) {
        return None;
    }
    Some(canonical)
}
pub fn select(path: &Path) -> Option<PathBuf> { trusted_fixed_executable_path(path) }
