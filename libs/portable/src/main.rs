#![windows_subsystem = "windows"]

#[cfg(windows)]
use bin_reader::InstallerPackage;
#[cfg(windows)]
use package_format::INSTALLER_MSI_NAME;

#[cfg(windows)]
mod bin_reader;
#[cfg(windows)]
mod package_format;

#[cfg(any(windows, test))]
const ELEVATED_INSTALL_ARG: &str = "--rustdesk-protected-install";
#[cfg(any(windows, test))]
const ELEVATED_SILENT_INSTALL_ARG: &str = "--rustdesk-protected-silent-install";

#[cfg(any(windows, test))]
fn parse_installer_invocation(args: &[std::ffi::OsString]) -> Result<(bool, bool), String> {
    match args {
        [] => Ok((false, false)),
        [arg] if arg == "--silent-install" => Ok((true, false)),
        [arg] if arg == ELEVATED_INSTALL_ARG => Ok((false, true)),
        [arg] if arg == ELEVATED_SILENT_INSTALL_ARG => Ok((true, true)),
        _ => Err("invalid setup command line".to_owned()),
    }
}

#[cfg(any(windows, test))]
fn is_accepted_msi_exit_code(code: u32) -> bool {
    matches!(code, 0 | 3010)
}

#[cfg(windows)]
fn has_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn main() {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    let (silent, protected) = match parse_installer_invocation(&args) {
        Ok(invocation) => invocation,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    let package = match InstallerPackage::embedded() {
        Ok(package) => package,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = win::run_protected_installer(package, silent, protected) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This installer requires Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
mod win {
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::windows::{ffi::OsStrExt, ffi::OsStringExt},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
            Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
            System::{
                ApplicationInstallationAndServicing::{
                    MsiInstallProductW, MsiSetInternalUI, INSTALLUILEVEL, INSTALLUILEVEL_DEFAULT,
                    INSTALLUILEVEL_NONE,
                },
                Com::CoTaskMemFree,
                Threading::{
                    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject,
                    INFINITE,
                },
            },
            UI::{
                Shell::{
                    FOLDERID_ProgramFiles, FOLDERID_ProgramFilesX86, SHGetKnownFolderPath,
                    ShellExecuteExW, KF_FLAG_DEFAULT, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
                },
                WindowsAndMessaging::SW_SHOWNORMAL,
            },
        },
    };

    use crate::{
        is_accepted_msi_exit_code, InstallerPackage, ELEVATED_INSTALL_ARG,
        ELEVATED_SILENT_INSTALL_ARG, INSTALLER_MSI_NAME,
    };

    const APP_INSTALL_DIR_NAME: &str = "RustDesk";
    const INSTALL_STAGING_PREFIX: &str = "RustDesk-staging";

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                if !self.0.is_invalid() {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    struct StagingDir {
        path: PathBuf,
    }

    impl Drop for StagingDir {
        fn drop(&mut self) {
            match fs::symlink_metadata(&self.path) {
                Ok(metadata)
                    if metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && !crate::has_reparse_point(&metadata) =>
                {
                    if let Err(err) = fs::remove_dir(&self.path) {
                        eprintln!(
                            "Failed to remove installer staging dir {}: {err}",
                            self.path.display()
                        );
                    }
                }
                Ok(_) => eprintln!(
                    "Refusing to remove non-directory or reparse installer staging path {}",
                    self.path.display()
                ),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => eprintln!(
                    "Failed to inspect installer staging dir {}: {err}",
                    self.path.display()
                ),
            }
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(Some(0)).collect()
    }

    fn wide_text(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }

    fn path_from_cotaskmem_pwstr(path: PWSTR, label: &str) -> Result<PathBuf, String> {
        let ptr = path.0;
        if ptr.is_null() {
            return Err(format!("{label} returned a null path"));
        }
        let mut len = 0usize;
        unsafe {
            while *ptr.add(len) != 0 {
                len += 1;
            }
            let value = OsString::from_wide(std::slice::from_raw_parts(ptr, len));
            CoTaskMemFree(Some(ptr as _));
            Ok(PathBuf::from(value))
        }
    }

    fn program_files_dir() -> Result<PathBuf, String> {
        let folder = if cfg!(target_pointer_width = "32") {
            &FOLDERID_ProgramFilesX86
        } else {
            &FOLDERID_ProgramFiles
        };
        let path = unsafe { SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, None) }
            .map_err(|err| format!("SHGetKnownFolderPath(Program Files) failed: {err}"))?;
        path_from_cotaskmem_pwstr(path, "SHGetKnownFolderPath(Program Files)")
    }

    fn normalized_windows_path_text(path: &Path) -> String {
        path.to_string_lossy()
            .trim_end_matches(['\\', '/'])
            .to_ascii_lowercase()
    }

    fn final_install_dir() -> Result<PathBuf, String> {
        Ok(program_files_dir()?.join(APP_INSTALL_DIR_NAME))
    }

    fn staging_is_outside_final_install_dir(staging: &Path) -> Result<bool, String> {
        let staging = normalized_windows_path_text(staging);
        let final_dir = normalized_windows_path_text(&final_install_dir()?);
        Ok(staging != final_dir && !staging.starts_with(&(final_dir + "\\")))
    }

    fn create_staging_dir() -> Result<StagingDir, String> {
        let root = program_files_dir()?;
        ensure_non_reparse_dir(&root)?;
        for attempt in 0..32 {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0);
            let path = root.join(format!(
                "{INSTALL_STAGING_PREFIX}-{}-{now}-{attempt}",
                std::process::id()
            ));
            if !staging_is_outside_final_install_dir(&path)? {
                return Err(format!(
                    "installer staging path overlaps the final install directory: {}",
                    path.display()
                ));
            }
            match fs::create_dir(&path) {
                Ok(()) => {
                    let metadata = fs::symlink_metadata(&path)
                        .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
                    if metadata.file_type().is_symlink() || crate::has_reparse_point(&metadata) {
                        return Err(format!(
                            "installer staging path is a reparse point: {}",
                            path.display()
                        ));
                    }
                    return Ok(StagingDir { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to create protected installer staging dir {}: {err}",
                        path.display()
                    ))
                }
            }
        }
        Err("failed to allocate protected installer staging dir".to_owned())
    }

    fn current_process_is_elevated() -> Result<bool, String> {
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
                .map_err(|err| format!("OpenProcessToken(current) failed: {err}"))?;
        }
        let token = HandleGuard(token);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                Some((&mut elevation) as *mut _ as *mut std::ffi::c_void),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            )
            .map_err(|err| format!("GetTokenInformation(TokenElevation) failed: {err}"))?;
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    fn relaunch_self_for_protected_install(silent: bool) -> Result<(), String> {
        let exe = std::env::current_exe()
            .map_err(|err| format!("failed to resolve current installer executable: {err}"))?;
        let operation = wide_text("runas");
        let file = wide(exe.as_os_str());
        let args = wide_text(if silent {
            ELEVATED_SILENT_INSTALL_ARG
        } else {
            ELEVATED_INSTALL_ARG
        });
        let mut info = SHELLEXECUTEINFOW {
            cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS,
            lpVerb: PCWSTR(operation.as_ptr()),
            lpFile: PCWSTR(file.as_ptr()),
            lpParameters: PCWSTR(args.as_ptr()),
            nShow: SW_SHOWNORMAL.0,
            ..Default::default()
        };
        unsafe {
            ShellExecuteExW(&mut info)
                .map_err(|err| format!("failed to relaunch protected installer: {err}"))?;
        }
        if info.hProcess.is_invalid() {
            return Err("protected installer relaunch returned no process handle".to_owned());
        }
        let process = HandleGuard(info.hProcess);
        let wait = unsafe { WaitForSingleObject(process.0, INFINITE) };
        if wait == WAIT_FAILED {
            return Err(format!(
                "failed to wait for protected installer relaunch: {}",
                std::io::Error::last_os_error()
            ));
        }
        if wait != WAIT_OBJECT_0 {
            return Err(format!(
                "protected installer relaunch returned unexpected wait state {}",
                wait.0
            ));
        }
        let mut exit_code = 0u32;
        unsafe {
            GetExitCodeProcess(process.0, &mut exit_code).map_err(|err| {
                format!("failed to read protected installer relaunch exit code: {err}")
            })?;
        }
        if exit_code != 0 {
            return Err(format!(
                "protected installer relaunch exited with code {exit_code}"
            ));
        }
        Ok(())
    }

    fn ensure_non_reparse_dir(path: &Path) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || crate::has_reparse_point(&metadata)
        {
            return Err(format!(
                "refusing to traverse non-directory or reparse path {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn ensure_clean_parent_chain(root: &Path, path: &Path) -> Result<(), String> {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("payload path escapes staging dir: {}", path.display()))?;
        let mut current = root.to_path_buf();
        ensure_non_reparse_dir(&current)?;
        for component in relative.components() {
            current.push(component);
            if current == path {
                break;
            }
            ensure_non_reparse_dir(&current)?;
        }
        Ok(())
    }

    fn remove_payload_file(root: &Path, file: &Path) -> Result<(), String> {
        match fs::symlink_metadata(file) {
            Ok(metadata) => {
                ensure_clean_parent_chain(root, file)?;
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || crate::has_reparse_point(&metadata)
                {
                    return Err(format!(
                        "refusing to remove non-file or reparse payload path {}",
                        file.display()
                    ));
                }
                fs::remove_file(file)
                    .map_err(|err| format!("failed to remove {}: {err}", file.display()))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(format!("failed to inspect {}: {err}", file.display())),
        }
    }

    fn finish_with_payload_cleanup(
        staging: &StagingDir,
        result: Result<(), String>,
    ) -> Result<(), String> {
        let cleanup = remove_payload_file(&staging.path, &staging.path.join(INSTALLER_MSI_NAME));
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(cleanup_err)) => Err(cleanup_err),
            (Err(err), Err(cleanup_err)) => Err(format!("{err}; cleanup failed: {cleanup_err}")),
        }
    }

    fn validate_staged_installer_msi(staging: &Path, msi: &Path) -> Result<(), String> {
        ensure_clean_parent_chain(staging, msi)?;
        let metadata = fs::symlink_metadata(msi)
            .map_err(|err| format!("failed to inspect staged MSI {}: {err}", msi.display()))?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || crate::has_reparse_point(&metadata)
        {
            return Err(format!(
                "staged MSI is not a regular non-reparse file: {}",
                msi.display()
            ));
        }
        Ok(())
    }

    struct InstallerUiLevelGuard(INSTALLUILEVEL);

    impl Drop for InstallerUiLevelGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = MsiSetInternalUI(self.0, None);
            }
        }
    }

    fn run_staged_msi(msi: &Path, silent: bool) -> Result<(), String> {
        let package_path = wide(msi.as_os_str());
        let properties = wide_text("REBOOT=ReallySuppress");
        let requested_ui = if silent {
            INSTALLUILEVEL_NONE
        } else {
            INSTALLUILEVEL_DEFAULT
        };
        let previous_ui = unsafe { MsiSetInternalUI(requested_ui, None) };
        let _ui_guard = InstallerUiLevelGuard(previous_ui);
        let code = unsafe {
            MsiInstallProductW(PCWSTR(package_path.as_ptr()), PCWSTR(properties.as_ptr()))
        };
        if is_accepted_msi_exit_code(code) {
            Ok(())
        } else {
            Err(format!("Windows Installer failed with code {code}"))
        }
    }

    pub(super) fn run_protected_installer(
        package: InstallerPackage<'_>,
        silent: bool,
        protected: bool,
    ) -> Result<(), String> {
        if !current_process_is_elevated()? {
            if protected {
                return Err(
                    "protected installer invocation requires an elevated process".to_owned(),
                );
            }
            return relaunch_self_for_protected_install(silent);
        }

        let staging = create_staging_dir()?;
        let result = package
            .write_to_new_file(&staging.path)
            .and_then(|msi| validate_staged_installer_msi(&staging.path, &msi).map(|_| msi))
            .and_then(|msi| run_staged_msi(&msi, silent));
        finish_with_payload_cleanup(&staging, result)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_accepted_msi_exit_code, parse_installer_invocation,
        ELEVATED_INSTALL_ARG, ELEVATED_SILENT_INSTALL_ARG,
    };

    #[test]
    fn accepts_only_windows_installer_success_statuses() {
        for code in [0, 3010] {
            assert!(is_accepted_msi_exit_code(code), "rejected {code}");
        }
        for code in [1, 1603, 1641, 3011, u32::MAX] {
            assert!(!is_accepted_msi_exit_code(code), "accepted {code}");
        }
    }

    #[test]
    fn setup_command_line_is_closed() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| std::ffi::OsString::from(*value))
                .collect::<Vec<_>>()
        };
        assert_eq!(parse_installer_invocation(&args(&[])), Ok((false, false)));
        assert_eq!(
            parse_installer_invocation(&args(&["--silent-install"])),
            Ok((true, false))
        );
        assert_eq!(
            parse_installer_invocation(&args(&[ELEVATED_INSTALL_ARG])),
            Ok((false, true))
        );
        assert_eq!(
            parse_installer_invocation(&args(&[ELEVATED_SILENT_INSTALL_ARG])),
            Ok((true, true))
        );
        assert!(parse_installer_invocation(&args(&["--unknown"])).is_err());
        assert!(parse_installer_invocation(&args(&["--silent-install", "--unknown"])).is_err());
        for value in [
            "--SILENT-INSTALL",
            "--silent-install ",
            "--silent-install=1",
            "\u{fffd}",
        ] {
            assert!(parse_installer_invocation(&args(&[value])).is_err());
        }

        #[cfg(unix)]
        {
            use std::{ffi::OsString, os::unix::ffi::OsStringExt};
            for prefix in [
                "",
                "--silent-install",
                ELEVATED_INSTALL_ARG,
                ELEVATED_SILENT_INSTALL_ARG,
            ] {
                let mut raw = prefix.as_bytes().to_vec();
                raw.push(0xff);
                let value = OsString::from_vec(raw);
                assert!(value.to_str().is_none());
                assert_eq!(
                    parse_installer_invocation(&[value]),
                    Err("invalid setup command line".to_owned())
                );
            }
        }
        #[cfg(windows)]
        {
            use std::{ffi::OsString, os::windows::ffi::OsStringExt};
            for prefix in [
                "",
                "--silent-install",
                ELEVATED_INSTALL_ARG,
                ELEVATED_SILENT_INSTALL_ARG,
            ] {
                let mut raw = prefix.encode_utf16().collect::<Vec<_>>();
                raw.push(0xd800);
                let value = OsString::from_wide(&raw);
                assert!(value.to_str().is_none());
                assert_eq!(
                    parse_installer_invocation(&[value]),
                    Err("invalid setup command line".to_owned())
                );
            }
        }
    }
}
