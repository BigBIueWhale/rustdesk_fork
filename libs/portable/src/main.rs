#![windows_subsystem = "windows"]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use bin_reader::{relative_payload_path, BinaryReader};

pub mod bin_reader;
#[cfg(windows)]
mod ui;

#[cfg(windows)]
const APP_METADATA: &[u8] = include_bytes!("../app_metadata.toml");
#[cfg(not(windows))]
const APP_METADATA: &[u8] = &[];
const APP_METADATA_CONFIG: &str = "meta.toml";
const META_LINE_PREFIX_TIMESTAMP: &str = "timestamp = ";
const APP_PREFIX: &str = "rustdesk";
const APPNAME_RUNTIME_ENV_KEY: &str = "RUSTDESK_APPNAME";
const ELEVATED_INSTALL_ARG: &str = "--rustdesk-protected-install";
const ELEVATED_SILENT_INSTALL_ARG: &str = "--rustdesk-protected-silent-install";
#[cfg(windows)]
const SET_FOREGROUND_WINDOW_ENV_KEY: &str = "SET_FOREGROUND_WINDOW";
const SETUP_EXE_NAME: &str = "rustdesk-setup.exe";
#[cfg(windows)]
const INSTALLER_MSI_NAME: &str = "rustdesk-installer.msi";

fn is_installer_filename(exe: &str) -> bool {
    let filename = exe.rsplit(['/', '\\']).next().unwrap_or_default();
    filename.eq_ignore_ascii_case(SETUP_EXE_NAME)
}

#[cfg(windows)]
fn current_exe_is_installer() -> Result<bool, String> {
    let path = std::env::current_exe()
        .map_err(|err| format!("failed to resolve current executable: {err}"))?;
    Ok(path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_installer_filename))
}

fn parse_installer_invocation(args: &[String]) -> Result<(bool, bool), String> {
    match args {
        [] => Ok((false, false)),
        [arg] if arg == "--silent-install" => Ok((true, false)),
        [arg] if arg == ELEVATED_INSTALL_ARG => Ok((false, true)),
        [arg] if arg == ELEVATED_SILENT_INSTALL_ARG => Ok((true, true)),
        _ => Err("invalid setup command line".to_owned()),
    }
}

fn is_accepted_msi_exit_code(code: u32) -> bool {
    matches!(code, 0 | 3010)
}

struct ExtractedPayload {
    exe: PathBuf,
}

fn is_timestamp_matches(dir: &Path, ts: &mut u64) -> bool {
    let Ok(app_metadata) = std::str::from_utf8(APP_METADATA) else {
        return true;
    };
    for line in app_metadata.lines() {
        if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
            if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                *ts = stored_ts;
                break;
            }
        }
    }
    if *ts == 0 {
        return true;
    }

    if let Ok(content) = std::fs::read_to_string(dir.join(APP_METADATA_CONFIG)) {
        for line in content.lines() {
            if line.starts_with(META_LINE_PREFIX_TIMESTAMP) {
                if let Ok(stored_ts) = line.replace(META_LINE_PREFIX_TIMESTAMP, "").parse::<u64>() {
                    return *ts == stored_ts;
                }
            }
        }
    }
    false
}

fn write_meta(dir: &Path, ts: u64) -> Result<(), String> {
    let meta_file = dir.join(APP_METADATA_CONFIG);
    if ts != 0 {
        let content = format!("{}{}", META_LINE_PREFIX_TIMESTAMP, ts);
        fs::write(&meta_file, content)
            .map_err(|err| format!("failed to write {}: {err}", meta_file.display()))?;
    }
    Ok(())
}

fn remove_setup_dir(dir: &Path) -> Result<(), String> {
    match fs::symlink_metadata(dir) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || has_reparse_point(&metadata) {
                return Err(format!(
                    "refusing to remove reparse-point setup dir {}",
                    dir.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(format!("setup path is not a directory: {}", dir.display()));
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(format!("failed to inspect {}: {err}", dir.display())),
    }
    fs::remove_dir_all(dir).map_err(|err| format!("failed to remove {}: {err}", dir.display()))
}

#[cfg(windows)]
fn has_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn has_reparse_point(_: &fs::Metadata) -> bool {
    false
}

fn extract_payload(reader: &BinaryReader, dir: &Path) -> Result<ExtractedPayload, String> {
    for file in reader.files.iter() {
        file.write_to_file(dir)?;
    }
    Ok(ExtractedPayload {
        exe: dir.join(relative_payload_path(&reader.exe)?),
    })
}

fn setup(
    reader: BinaryReader,
    dir: Option<PathBuf>,
    clear: bool,
    _args: &Vec<String>,
    _ui: &mut bool,
) -> Option<PathBuf> {
    let dir = if let Some(dir) = dir {
        dir
    } else {
        // home dir
        if let Some(dir) = dirs::data_local_dir() {
            dir.join(APP_PREFIX)
        } else {
            eprintln!("not found data local dir");
            return None;
        }
    };

    let mut ts = 0;
    if clear || !is_timestamp_matches(&dir, &mut ts) {
        #[cfg(windows)]
        if _args.is_empty() {
            *_ui = true;
            ui::setup();
        }
        if let Err(err) = remove_setup_dir(&dir) {
            eprintln!("{err}");
            return None;
        }
    }
    let payload = match extract_payload(&reader, &dir) {
        Ok(payload) => payload,
        Err(err) => {
            eprintln!("{err}");
            return None;
        }
    };
    if let Err(err) = write_meta(&dir, ts) {
        eprintln!("{err}");
        return None;
    }
    #[cfg(linux)]
    reader.configure_permission(&dir);
    Some(payload.exe)
}

fn use_null_stdio() -> bool {
    #[cfg(windows)]
    {
        // When running in CMD on Windows 7, using Stdio::inherit() with spawn returns an "invalid handle" error.
        // Since using Stdio::null() didn’t cause any issues, and determining whether the program is launched from CMD or by double-clicking would require calling more APIs during startup, we also use Stdio::null() when launched by double-clicking on Windows 7.
        let is_windows_7 = is_windows_7();
        println!("is windows7: {}", is_windows_7);
        return is_windows_7;
    }
    #[cfg(not(windows))]
    false
}

#[cfg(windows)]
fn is_windows_7() -> bool {
    use windows::Wdk::System::SystemServices::RtlGetVersion;
    use windows::Win32::System::SystemInformation::OSVERSIONINFOW;

    unsafe {
        let mut version_info = OSVERSIONINFOW::default();
        version_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;

        if RtlGetVersion(&mut version_info).is_ok() {
            // Windows 7 is version 6.1
            println!(
                "Windows version: {}.{}",
                version_info.dwMajorVersion, version_info.dwMinorVersion
            );
            return version_info.dwMajorVersion == 6 && version_info.dwMinorVersion == 1;
        }
    }
    false
}

fn execute(path: PathBuf, args: Vec<String>, _ui: bool) {
    println!("executing {}", path.display());
    // setup env
    let exe = std::env::current_exe().unwrap_or_default();
    let exe_name = exe.file_name().unwrap_or_default();
    // run executable
    let mut cmd = Command::new(path);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
        if _ui {
            cmd.env(SET_FOREGROUND_WINDOW_ENV_KEY, "1");
        }
    }

    cmd.env(APPNAME_RUNTIME_ENV_KEY, exe_name);
    if use_null_stdio() {
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    }
    let _child = cmd.spawn();

    #[cfg(windows)]
    if _ui {
        match _child {
            Ok(child) => unsafe {
                winapi::um::winuser::AllowSetForegroundWindow(child.id() as u32);
            },
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }
}

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    #[cfg(windows)]
    let installer_mode = match current_exe_is_installer() {
        Ok(installer_mode) => installer_mode,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    #[cfg(windows)]
    if installer_mode {
        let (silent, protected) = match parse_installer_invocation(&args) {
            Ok(invocation) => invocation,
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        };
        let reader = BinaryReader::default();
        if let Err(err) = win::run_protected_installer(reader, silent, protected) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    if args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--silent-install" | ELEVATED_INSTALL_ARG | ELEVATED_SILENT_INSTALL_ARG
        )
    }) {
        eprintln!("installer-only argument requires {SETUP_EXE_NAME}");
        std::process::exit(1);
    }
    let mut ui = false;
    let reader = BinaryReader::default();
    if let Some(exe) = setup(reader, None, false, &args, &mut ui) {
        execute(exe, args, ui);
    }
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
        is_accepted_msi_exit_code, relative_payload_path, BinaryReader, ELEVATED_INSTALL_ARG,
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

    fn remove_empty_payload_dirs(root: &Path, files: &[PathBuf]) -> Result<(), String> {
        let mut dirs = Vec::new();
        for file in files {
            let mut current = file.parent();
            while let Some(dir) = current {
                if dir == root {
                    break;
                }
                dirs.push(dir.to_path_buf());
                current = dir.parent();
            }
        }
        dirs.sort_by(|left, right| {
            right
                .components()
                .count()
                .cmp(&left.components().count())
                .then_with(|| right.cmp(left))
        });
        dirs.dedup();
        let mut errors = Vec::new();
        for dir in dirs {
            match fs::symlink_metadata(&dir) {
                Ok(metadata)
                    if metadata.is_dir()
                        && !metadata.file_type().is_symlink()
                        && !crate::has_reparse_point(&metadata) => {}
                Ok(_) => {
                    errors.push(format!(
                        "refusing to remove non-directory or reparse payload path {}",
                        dir.display()
                    ));
                    continue;
                }
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    errors.push(format!("failed to inspect {}: {err}", dir.display()));
                    continue;
                }
            }
            match fs::remove_dir(&dir) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => errors.push(format!(
                    "failed to remove payload dir {}: {err}",
                    dir.display()
                )),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn cleanup_extracted_payload(root: &Path, files: &[PathBuf]) -> Result<(), String> {
        let mut errors = Vec::new();
        for file in files.iter().rev() {
            if let Err(err) = remove_payload_file(root, file) {
                errors.push(err);
            }
        }
        if let Err(err) = remove_empty_payload_dirs(root, files) {
            errors.push(err);
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    fn finish_with_manifest_cleanup(
        staging: &StagingDir,
        files: &[PathBuf],
        result: Result<(), String>,
    ) -> Result<(), String> {
        let cleanup = cleanup_extracted_payload(&staging.path, files);
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(cleanup_err)) => Err(cleanup_err),
            (Err(err), Err(cleanup_err)) => Err(format!("{err}; cleanup failed: {cleanup_err}")),
        }
    }

    fn installer_manifest_paths(
        reader: &BinaryReader,
        staging: &Path,
    ) -> Result<Vec<PathBuf>, String> {
        reader
            .files
            .iter()
            .map(|file| relative_payload_path(&file.path).map(|path| staging.join(path)))
            .collect()
    }

    fn extract_installer_payload(reader: &BinaryReader, staging: &Path) -> Result<(), String> {
        for file in &reader.files {
            file.write_to_new_file(staging)?;
        }
        Ok(())
    }

    fn installer_msi_from_manifest(staging: &Path, files: &[PathBuf]) -> Result<PathBuf, String> {
        let msi = staging.join(INSTALLER_MSI_NAME);
        if files.len() != 1 || files.first() != Some(&msi) {
            return Err(format!(
                "embedded setup payload must contain only root {INSTALLER_MSI_NAME}"
            ));
        }
        Ok(msi)
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
        reader: BinaryReader,
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
        let files = installer_manifest_paths(&reader, &staging.path)?;
        let result = installer_msi_from_manifest(&staging.path, &files)
            .and_then(|msi| extract_installer_payload(&reader, &staging.path).map(|_| msi))
            .and_then(|msi| validate_staged_installer_msi(&staging.path, &msi).map(|_| msi))
            .and_then(|msi| run_staged_msi(&msi, silent));
        finish_with_manifest_cleanup(&staging, &files, result)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        is_accepted_msi_exit_code, is_installer_filename, parse_installer_invocation,
        ELEVATED_INSTALL_ARG, ELEVATED_SILENT_INSTALL_ARG,
    };

    #[test]
    fn classifies_only_supported_installer_filenames() {
        assert!(is_installer_filename("rustdesk-setup.exe"));
        assert!(is_installer_filename(r"C:\\release\\RUSTDESK-SETUP.EXE"));
        assert!(!is_installer_filename("rustdesk-1.4.7-install.exe"));
        assert!(!is_installer_filename("install.exe"));
        assert!(!is_installer_filename("rustdeskinstall.exe"));
        assert!(!is_installer_filename("rustdesk-uninstall.exe"));
        assert!(!is_installer_filename("rustdesk-setup.exe.bak"));
        assert!(!is_installer_filename("rustdesk.exe"));
    }

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
                .map(|value| (*value).to_owned())
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
    }
}
