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
#[cfg(windows)]
const ELEVATED_INSTALL_ARG: &str = "--rustdesk-protected-install";
#[cfg(windows)]
const ELEVATED_SILENT_INSTALL_ARG: &str = "--rustdesk-protected-silent-install";
#[cfg(windows)]
const PROTECTED_INSTALL_ENV_KEY: &str = "RUSTDESK_PROTECTED_INSTALL";
#[cfg(windows)]
const SET_FOREGROUND_WINDOW_ENV_KEY: &str = "SET_FOREGROUND_WINDOW";

struct ExtractedPayload {
    exe: PathBuf,
    #[cfg_attr(not(windows), allow(dead_code))]
    files: Vec<PathBuf>,
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
    let mut files = Vec::with_capacity(reader.files.len());
    for file in reader.files.iter() {
        files.push(file.write_to_file(dir)?);
    }
    Ok(ExtractedPayload {
        exe: dir.join(relative_payload_path(&reader.exe)?),
        files,
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
    #[cfg(windows)]
    if let Err(err) = win::copy_runtime_broker(&dir) {
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
    let mut args = Vec::new();
    let mut arg_exe = Default::default();
    let mut i = 0;
    for arg in std::env::args() {
        if i == 0 {
            arg_exe = arg.clone();
        } else {
            args.push(arg);
        }
        i += 1;
    }
    let click_setup = args.is_empty() && arg_exe.to_lowercase().ends_with("install.exe");
    #[cfg(windows)]
    let silent_install = args.iter().any(|arg| arg == "--silent-install");
    #[cfg(windows)]
    let protected_install = args.len() == 1
        && (args[0] == ELEVATED_INSTALL_ARG || args[0] == ELEVATED_SILENT_INSTALL_ARG);
    #[cfg(windows)]
    if click_setup || silent_install || protected_install {
        let reader = BinaryReader::default();
        let silent = silent_install
            || (protected_install
                && args
                    .first()
                    .is_some_and(|arg| arg == ELEVATED_SILENT_INSTALL_ARG));
        if let Err(err) = win::run_protected_installer(reader, silent) {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(windows)]
    let quick_support = args.is_empty() && win::is_quick_support_exe(&arg_exe);
    #[cfg(not(windows))]
    let quick_support = false;

    let mut ui = false;
    let reader = BinaryReader::default();
    if let Some(exe) = setup(
        reader,
        None,
        click_setup || args.contains(&"--silent-install".to_owned()),
        &args,
        &mut ui,
    ) {
        if click_setup {
            args = vec!["--install".to_owned()];
        } else if quick_support {
            args = vec!["--quick_support".to_owned()];
        }
        execute(exe, args, ui);
    }
}

#[cfg(windows)]
mod win {
    use std::{
        ffi::{OsStr, OsString},
        fs,
        os::windows::{ffi::OsStrExt, ffi::OsStringExt, process::CommandExt},
        path::{Path, PathBuf},
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{CloseHandle, HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
            Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
            System::{
                Com::CoTaskMemFree,
                SystemInformation::GetSystemDirectoryW,
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
        extract_payload, write_meta, BinaryReader, ELEVATED_INSTALL_ARG,
        ELEVATED_SILENT_INSTALL_ARG, PROTECTED_INSTALL_ENV_KEY,
    };

    const APP_INSTALL_DIR_NAME: &str = "RustDesk";
    const INSTALL_STAGING_PREFIX: &str = "RustDesk-staging";

    // Used for privacy mode(magnifier impl).
    pub const RUNTIME_BROKER_EXE: &'static str = "C:\\Windows\\System32\\RuntimeBroker.exe";
    pub const WIN_TOPMOST_INJECTED_PROCESS_EXE: &'static str = "RuntimeBroker_rustdesk.exe";

    fn trusted_system_dir() -> Result<PathBuf, String> {
        let mut buffer = [0u16; 260];
        let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
        if len == 0 {
            return Err(format!(
                "GetSystemDirectoryW failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if len >= buffer.len() {
            return Err("GetSystemDirectoryW returned an oversized path".to_owned());
        }
        Ok(PathBuf::from(OsString::from_wide(&buffer[..len])))
    }

    fn trusted_system_tool_path(tool: &str) -> Result<PathBuf, String> {
        if tool.contains('\\') || tool.contains('/') || tool.contains('"') || tool.trim() != tool {
            return Err(format!("invalid trusted system tool name: {tool}"));
        }
        let path = trusted_system_dir()?.join(tool);
        if !path.is_file() {
            return Err(format!("trusted system tool not found: {}", path.display()));
        }
        Ok(path)
    }

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

    fn current_launcher_name() -> OsString {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_os_string()))
            .unwrap_or_else(|| OsString::from(APP_INSTALL_DIR_NAME))
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
        for dir in dirs {
            ensure_non_reparse_dir(&dir)?;
            match fs::remove_dir(&dir) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    return Err(format!(
                        "failed to remove payload dir {}: {err}",
                        dir.display()
                    ))
                }
            }
        }
        Ok(())
    }

    fn cleanup_extracted_payload(root: &Path, files: &[PathBuf]) -> Result<(), String> {
        let mut files = files.to_vec();
        files.push(root.join(WIN_TOPMOST_INJECTED_PROCESS_EXE));
        for file in files.iter().rev() {
            remove_payload_file(root, file)?;
        }
        remove_empty_payload_dirs(root, &files)
    }

    fn finish_with_payload_cleanup(
        staging: &StagingDir,
        payload: &crate::ExtractedPayload,
        result: Result<(), String>,
    ) -> Result<(), String> {
        let cleanup = cleanup_extracted_payload(&staging.path, &payload.files);
        match (result, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) => Err(err),
            (Ok(()), Err(cleanup_err)) => Err(cleanup_err),
            (Err(err), Err(cleanup_err)) => Err(format!("{err}; cleanup failed: {cleanup_err}")),
        }
    }

    pub(super) fn run_protected_installer(
        reader: BinaryReader,
        silent: bool,
    ) -> Result<(), String> {
        if !current_process_is_elevated()? {
            return relaunch_self_for_protected_install(silent);
        }

        let staging = create_staging_dir()?;
        let payload = extract_payload(&reader, &staging.path)?;
        let prepare = write_meta(&staging.path, 0).and_then(|_| copy_runtime_broker(&staging.path));
        if let Err(err) = prepare {
            return finish_with_payload_cleanup(&staging, &payload, Err(err));
        }

        let mut cmd = Command::new(&payload.exe);
        let install_arg = if silent {
            "--silent-install"
        } else {
            "--install"
        };
        cmd.arg(install_arg)
            .env(super::APPNAME_RUNTIME_ENV_KEY, current_launcher_name())
            .env(PROTECTED_INSTALL_ENV_KEY, "1")
            .env(super::SET_FOREGROUND_WINDOW_ENV_KEY, "1")
            .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW);
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(err) => {
                return finish_with_payload_cleanup(
                    &staging,
                    &payload,
                    Err(format!("failed to start protected installer UI: {err}")),
                );
            }
        };
        unsafe {
            winapi::um::winuser::AllowSetForegroundWindow(child.id());
        }
        let result = match child.wait() {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(format!("protected installer UI exited with {status}")),
            Err(err) => Err(format!("failed to wait for protected installer UI: {err}")),
        };
        finish_with_payload_cleanup(&staging, &payload, result)
    }

    pub(super) fn copy_runtime_broker(dir: &Path) -> Result<(), String> {
        let src = RUNTIME_BROKER_EXE;
        let tgt = WIN_TOPMOST_INJECTED_PROCESS_EXE;
        let target_file = dir.join(tgt);
        if target_file.exists() {
            if let (Ok(src_file), Ok(tgt_file)) = (fs::read(src), fs::read(&target_file)) {
                let src_md5 = format!("{:x}", md5::compute(&src_file));
                let tgt_md5 = format!("{:x}", md5::compute(&tgt_file));
                if src_md5 == tgt_md5 {
                    return Ok(());
                }
            }
        }
        match trusted_system_tool_path("taskkill.exe") {
            Ok(taskkill) => {
                if let Err(err) = Command::new(taskkill)
                    .args(&["/F", "/IM", "RuntimeBroker_rustdesk.exe"])
                    .creation_flags(winapi::um::winbase::CREATE_NO_WINDOW)
                    .output()
                {
                    eprintln!("RuntimeBroker cleanup failed: {}", err);
                }
            }
            Err(err) => {
                eprintln!("Skipping RuntimeBroker cleanup: {}", err);
            }
        }
        fs::copy(src, &target_file).map_err(|err| {
            format!(
                "failed to copy {} into {}: {err}",
                src,
                target_file.display()
            )
        })?;
        Ok(())
    }

    /// Check if the executable is a Quick Support version.
    /// Note: This function must be kept in sync with `src/core_main.rs`.
    #[inline]
    pub(super) fn is_quick_support_exe(exe: &str) -> bool {
        let exe = exe.to_lowercase();
        exe.contains("-qs-") || exe.contains("-qs.exe") || exe.contains("_qs.exe")
    }
}
