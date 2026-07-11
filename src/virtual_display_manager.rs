use hbb_common::{platform::windows, ResultType};

pub const AMYUNI_IDD_DEVICE_STRING: &'static str = "USB Mobile Monitor Virtual Display\0";

const IDD_IMPL_AMYUNI: &str = "amyuni_idd";

#[derive(Debug, Copy, Clone)]
pub struct MonitorMode {
    pub width: u32,
    pub height: u32,
    pub sync: u32,
}

pub fn is_amyuni_idd() -> bool {
    true
}

pub fn get_cur_device_string() -> &'static str {
    AMYUNI_IDD_DEVICE_STRING
}

pub fn is_virtual_display_supported() -> bool {
    #[cfg(target_os = "windows")]
    {
        windows::is_windows_version_or_greater(10, 0, 19041, 0, 0)
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

pub fn plug_in_headless() -> ResultType<()> {
    amyuni_idd::plug_in_headless()
}

pub fn get_platform_additions() -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    if !crate::platform::windows::is_self_service_running() {
        return map;
    }
    map.insert("idd_impl".into(), serde_json::json!(IDD_IMPL_AMYUNI));
    let c = amyuni_idd::get_monitor_count();
    if c > 0 {
        map.insert("amyuni_virtual_displays".into(), serde_json::json!(c));
    }
    map
}

#[inline]
pub fn plug_in_monitor(_idx: u32, _modes: Vec<MonitorMode>) -> ResultType<()> {
    amyuni_idd::plug_in_monitor()
}

pub fn plug_out_monitor(index: i32, force_all: bool, force_one: bool) -> ResultType<()> {
    amyuni_idd::plug_out_monitor(index, force_all, force_one)
}

pub fn plug_in_peer_request(_modes: Vec<Vec<MonitorMode>>) -> ResultType<Vec<u32>> {
    amyuni_idd::plug_in_monitor()?;
    Ok(vec![0])
}

pub fn plug_out_monitor_indices(
    indices: &[u32],
    force_all: bool,
    force_one: bool,
) -> ResultType<()> {
    for _idx in indices.iter() {
        amyuni_idd::plug_out_monitor(0, force_all, force_one)?;
    }
    Ok(())
}

pub fn reset_all() -> ResultType<()> {
    amyuni_idd::reset_all()
}

pub mod amyuni_idd {
    use super::windows;
    use crate::platform::{reg_display_settings, win_device};
    use hbb_common::{anyhow::anyhow, bail, lazy_static, log, tokio::time::Instant, ResultType};
    use std::{
        ffi::OsStr,
        fs, io, mem,
        os::windows::{ffi::OsStrExt, fs::MetadataExt},
        path::{Path, PathBuf},
        ptr::null_mut,
        sync::{atomic, Arc, Mutex},
        time::Duration,
    };
    use winapi::{
        shared::{
            guiddef::GUID,
            minwindef::FALSE,
            winerror::{ERROR_NO_MORE_ITEMS, ERROR_SUCCESS_REBOOT_REQUIRED, WAIT_TIMEOUT},
        },
        um::{
            fileapi::{
                CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, OPEN_EXISTING,
            },
            handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
            processthreadsapi::{
                CreateProcessW, GetExitCodeProcess, PROCESS_INFORMATION, STARTUPINFOW,
            },
            synchapi::WaitForSingleObject,
            winbase::{CREATE_NO_WINDOW, FILE_FLAG_BACKUP_SEMANTICS, WAIT_OBJECT_0},
            winnt::{
                FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, HANDLE,
            },
        },
    };

    const IDD_DRIVER_DIR: &str = "usbmmidd_v2";
    const INF_FILE: &str = "usbmmIdd.inf";
    const INTERFACE_GUID: GUID = GUID {
        Data1: 0xb5ffd75f,
        Data2: 0xda40,
        Data3: 0x4353,
        Data4: [0x8f, 0xf8, 0xb6, 0xda, 0xf6, 0xf1, 0xd8, 0xca],
    };
    const HARDWARE_ID: &str = "usbmmidd";
    const PLUG_MONITOR_IO_CONTROL_CDOE: u32 = 2307084;
    const INSTALLER_EXE_FILE: &str = "deviceinstaller64.exe";
    const DEVICEINSTALLER64_TIMEOUT_MS: u32 = 120_000;
    const FILE_ATTRIBUTE_REPARSE_POINT_FLAG: u32 = 0x400;

    struct DeviceInstaller64Paths {
        work_dir: Vec<u16>,
        exe_path: Vec<u16>,
    }

    enum DeviceInstaller64RebootPolicy {
        Accept,
        Reject,
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct WindowsPathIdentity {
        volume_serial_number: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    lazy_static::lazy_static! {
        static ref LOCK: Arc<Mutex<()>> = Default::default();
        static ref LAST_PLUG_IN_HEADLESS_TIME: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    }
    const VIRTUAL_DISPLAY_MAX_COUNT: usize = 4;
    // The count of virtual displays plugged in.
    // This count is not accurate, because:
    // 1. The virtual display driver may also be controlled by other processes.
    // 2. RustDesk may crash and restart, but the virtual displays are kept.
    //
    // to-do: Maybe a better way is to add an option asking the user if plug out all virtual displays on disconnect.
    static VIRTUAL_DISPLAY_COUNT: atomic::AtomicUsize = atomic::AtomicUsize::new(0);

    fn wide_null(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn path_identity(path: &Path, label: &str) -> ResultType<WindowsPathIdentity> {
        let path_w = wide_null(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                path_w.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            bail!(
                "Failed to open {label} for identity '{}': {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        let _guard = HandleGuard(handle);
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { mem::zeroed() };
        let ok = unsafe { GetFileInformationByHandle(handle, &mut info) };
        if ok == 0 {
            bail!(
                "Failed to query {label} identity '{}': {}",
                path.display(),
                io::Error::last_os_error()
            );
        }
        Ok(WindowsPathIdentity {
            volume_serial_number: info.dwVolumeSerialNumber,
            file_index_high: info.nFileIndexHigh,
            file_index_low: info.nFileIndexLow,
        })
    }

    fn deviceinstaller64_command_line(paths: &DeviceInstaller64Paths, args: &str) -> Vec<u16> {
        let mut command_line = Vec::with_capacity(paths.exe_path.len() + args.len() + 4);
        command_line.push('"' as u16);
        command_line.extend(paths.exe_path.iter().copied().take_while(|ch| *ch != 0));
        command_line.push('"' as u16);
        if !args.is_empty() {
            command_line.push(' ' as u16);
            command_line.extend(OsStr::new(args).encode_wide());
        }
        command_line.push(0);
        command_line
    }

    fn has_reparse_point(metadata: &fs::Metadata) -> bool {
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT_FLAG != 0
    }

    fn require_regular_dir_metadata(
        path: &Path,
        label: &str,
        metadata: &fs::Metadata,
    ) -> ResultType<()> {
        if !metadata.is_dir() || metadata.file_type().is_symlink() || has_reparse_point(metadata) {
            bail!("{label} is not a trusted directory: {}", path.display());
        }
        Ok(())
    }

    fn require_regular_file_metadata(
        path: &Path,
        label: &str,
        metadata: &fs::Metadata,
    ) -> ResultType<()> {
        if !metadata.is_file() || metadata.file_type().is_symlink() || has_reparse_point(metadata) {
            bail!("{label} is not a trusted file: {}", path.display());
        }
        Ok(())
    }

    fn require_existing_directory_no_reparse(path: &Path, label: &str) -> ResultType<()> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| anyhow!("{label} is not accessible '{}': {err}", path.display()))?;
        require_regular_dir_metadata(path, label, &metadata)
    }

    fn require_existing_file_no_reparse(path: &Path, label: &str) -> ResultType<()> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| anyhow!("{label} is not accessible '{}': {err}", path.display()))?;
        require_regular_file_metadata(path, label, &metadata)
    }

    fn optional_existing_directory_no_reparse(path: &Path, label: &str) -> ResultType<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                require_regular_dir_metadata(path, label, &metadata)?;
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => {
                Err(anyhow!("{label} is not accessible '{}': {err}", path.display()).into())
            }
        }
    }

    fn optional_existing_file_no_reparse(path: &Path, label: &str) -> ResultType<bool> {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                require_regular_file_metadata(path, label, &metadata)?;
                Ok(true)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => {
                Err(anyhow!("{label} is not accessible '{}': {err}", path.display()).into())
            }
        }
    }

    fn trusted_install_dir() -> ResultType<PathBuf> {
        let current_exe = std::env::current_exe()
            .map_err(|err| anyhow!("Failed to resolve current executable: {err}"))?;
        let current_dir = current_exe
            .parent()
            .ok_or_else(|| anyhow!("Cannot get parent of current exe file."))?;
        let install_dir = crate::platform::windows::fixed_service_install_path("")?;
        let expected_exe = install_dir.join(format!("{}.exe", crate::get_app_name()));

        require_existing_directory_no_reparse(&install_dir, "Windows service install directory")?;
        require_existing_directory_no_reparse(current_dir, "Windows current executable directory")?;
        require_existing_file_no_reparse(&current_exe, "Windows current executable")?;
        require_existing_file_no_reparse(&expected_exe, "Windows fixed service executable")?;

        if path_identity(current_dir, "Windows current executable directory")?
            != path_identity(&install_dir, "Windows service install directory")?
        {
            bail!(
                "Amyuni IDD helper requires the fixed installed service directory: {}",
                install_dir.display()
            );
        }
        if path_identity(&current_exe, "Windows current executable")?
            != path_identity(&expected_exe, "Windows fixed service executable")?
        {
            bail!(
                "Amyuni IDD helper requires the fixed installed service executable: {}",
                expected_exe.display()
            );
        }

        Ok(install_dir)
    }

    fn trusted_amyuni_work_dir() -> ResultType<PathBuf> {
        Ok(trusted_install_dir()?.join(IDD_DRIVER_DIR))
    }

    fn get_deviceinstaller64_paths() -> ResultType<Option<DeviceInstaller64Paths>> {
        let work_dir = trusted_amyuni_work_dir()?;
        if !optional_existing_directory_no_reparse(&work_dir, "Amyuni IDD directory")? {
            return Ok(None);
        }
        let exe_path = work_dir.join(INSTALLER_EXE_FILE);
        if !optional_existing_file_no_reparse(&exe_path, "Amyuni IDD helper")? {
            return Ok(None);
        }

        Ok(Some(DeviceInstaller64Paths {
            work_dir: wide_null(work_dir.as_os_str()),
            exe_path: wide_null(exe_path.as_os_str()),
        }))
    }

    fn get_amyuni_inf_path() -> ResultType<PathBuf> {
        let work_dir = trusted_amyuni_work_dir()?;
        require_existing_directory_no_reparse(&work_dir, "Amyuni IDD directory")?;
        let inf_path = work_dir.join(INF_FILE);
        require_existing_file_no_reparse(&inf_path, "Amyuni IDD INF")?;
        Ok(inf_path)
    }

    pub fn uninstall_driver() -> ResultType<()> {
        if let Some(paths) = get_deviceinstaller64_paths()? {
            if crate::platform::windows::is_x64() {
                log::info!("Uninstalling driver by deviceinstaller64.exe");
                install_if_x86_on_x64(
                    &paths,
                    "remove usbmmidd",
                    DeviceInstaller64RebootPolicy::Accept,
                )?;
                // Sleep some time to wait for the driver to be uninstalled.
                std::thread::sleep(Duration::from_secs(2));
                return Ok(());
            }
        }

        log::info!("Uninstalling driver by SetupAPI");
        let mut reboot_required = false;
        let _ = unsafe { win_device::uninstall_driver(HARDWARE_ID, &mut reboot_required)? };
        Ok(())
    }

    // SetupDiCallClassInstaller() will always fail if current_exe() is built as x86 and running on x64.
    // So we need to call another x64 version exe to install and uninstall the driver.
    fn install_if_x86_on_x64(
        paths: &DeviceInstaller64Paths,
        args: &str,
        reboot_policy: DeviceInstaller64RebootPolicy,
    ) -> ResultType<()> {
        let mut command_line = deviceinstaller64_command_line(paths, args);
        let mut startup_info: STARTUPINFOW = unsafe { mem::zeroed() };
        startup_info.cb = mem::size_of::<STARTUPINFOW>() as u32;
        let mut process_info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                paths.exe_path.as_ptr(),
                command_line.as_mut_ptr(),
                null_mut(),
                null_mut(),
                FALSE,
                CREATE_NO_WINDOW,
                null_mut(),
                paths.work_dir.as_ptr(),
                &mut startup_info,
                &mut process_info,
            )
        };
        if created == FALSE {
            bail!(
                "Failed to run deviceinstaller64.exe: {}",
                io::Error::last_os_error()
            );
        }

        let process = HandleGuard(process_info.hProcess);
        let _thread = HandleGuard(process_info.hThread);
        let wait_result = unsafe { WaitForSingleObject(process.0, DEVICEINSTALLER64_TIMEOUT_MS) };
        if wait_result == WAIT_TIMEOUT {
            bail!("Timed out waiting for deviceinstaller64.exe");
        }
        if wait_result != WAIT_OBJECT_0 {
            bail!(
                "Failed to wait for deviceinstaller64.exe: {}",
                io::Error::last_os_error()
            );
        }

        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == FALSE {
            bail!(
                "Failed to read deviceinstaller64.exe exit code: {}",
                io::Error::last_os_error()
            );
        }
        if exit_code == ERROR_SUCCESS_REBOOT_REQUIRED {
            match reboot_policy {
                DeviceInstaller64RebootPolicy::Accept => {
                    log::info!("deviceinstaller64.exe completed with reboot required");
                }
                DeviceInstaller64RebootPolicy::Reject => {
                    bail!("deviceinstaller64.exe requires reboot before the driver can be used");
                }
            }
        } else if exit_code != 0 {
            bail!("deviceinstaller64.exe failed with exit code {exit_code}");
        }
        Ok(())
    }

    // If the driver is installed by "deviceinstaller64.exe", the driver will be installed asynchronously.
    // The caller must wait some time before using the driver.
    fn check_install_driver(is_async: &mut bool) -> ResultType<()> {
        let _l = LOCK.lock().unwrap();
        let drivers = windows::get_display_drivers();
        if drivers
            .iter()
            .any(|(s, c)| s == super::AMYUNI_IDD_DEVICE_STRING && *c == 0)
        {
            *is_async = false;
            return Ok(());
        }

        if let Some(paths) = get_deviceinstaller64_paths()? {
            if crate::platform::windows::is_x64() {
                log::info!("Installing driver by deviceinstaller64.exe");
                install_if_x86_on_x64(
                    &paths,
                    "install usbmmidd.inf usbmmidd",
                    DeviceInstaller64RebootPolicy::Reject,
                )?;
                *is_async = true;
                return Ok(());
            }
        }

        let inf_path = get_amyuni_inf_path()?;
        let inf_path = inf_path.to_str().ok_or_else(|| {
            anyhow!(
                "Amyuni IDD INF path is not valid UTF-8: {}",
                inf_path.display()
            )
        })?;

        log::info!("Installing driver by SetupAPI");
        let mut reboot_required = false;
        unsafe { win_device::install_driver(inf_path, HARDWARE_ID, &mut reboot_required)? };
        if reboot_required {
            bail!("SetupAPI driver install requires reboot before the driver can be used");
        }
        *is_async = false;
        Ok(())
    }

    pub fn reset_all() -> ResultType<()> {
        let _ = crate::privacy_mode::turn_off_privacy(0, None);
        let _ = plug_out_monitor(super::IDD_PLUG_OUT_ALL_INDEX, true, false);
        *LAST_PLUG_IN_HEADLESS_TIME.lock().unwrap() = None;
        Ok(())
    }

    #[inline]
    fn plug_monitor_(
        add: bool,
        wait_timeout: Option<Duration>,
    ) -> Result<(), win_device::DeviceError> {
        let cmd = if add { 0x10 } else { 0x00 };
        let cmd = [cmd, 0x00, 0x00, 0x00];
        let now = Instant::now();
        let c1 = get_monitor_count();
        unsafe {
            win_device::device_io_control(&INTERFACE_GUID, PLUG_MONITOR_IO_CONTROL_CDOE, &cmd, 0)?;
        }
        if let Some(wait_timeout) = wait_timeout {
            while now.elapsed() < wait_timeout {
                if get_monitor_count() != c1 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
        }
        // No need to consider concurrency here.
        if add {
            // If the monitor is plugged in, increase the count.
            // Though there's already a check of `VIRTUAL_DISPLAY_MAX_COUNT`, it's still better to check here for double ensure.
            if VIRTUAL_DISPLAY_COUNT.load(atomic::Ordering::SeqCst) < VIRTUAL_DISPLAY_MAX_COUNT {
                VIRTUAL_DISPLAY_COUNT.fetch_add(1, atomic::Ordering::SeqCst);
            }
        } else {
            if VIRTUAL_DISPLAY_COUNT.load(atomic::Ordering::SeqCst) > 0 {
                VIRTUAL_DISPLAY_COUNT.fetch_sub(1, atomic::Ordering::SeqCst);
            }
        }
        Ok(())
    }

    // `std::thread::sleep()` with a timeout is acceptable here.
    // Because user can wait for a while to plug in a monitor.
    fn plug_in_monitor_(
        add: bool,
        is_driver_async_installed: bool,
        wait_timeout: Option<Duration>,
    ) -> ResultType<()> {
        let timeout = Duration::from_secs(3);
        let now = Instant::now();
        let reg_connectivity_old = reg_display_settings::read_reg_connectivity();
        loop {
            match plug_monitor_(add, wait_timeout) {
                Ok(_) => {
                    break;
                }
                Err(e) => {
                    if is_driver_async_installed {
                        if let win_device::DeviceError::WinApiLastErr(_, e2) = &e {
                            if e2.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as _) {
                                if now.elapsed() < timeout {
                                    std::thread::sleep(Duration::from_millis(100));
                                    continue;
                                }
                            }
                        }
                    }
                    return Err(e.into());
                }
            }
        }
        // Workaround for the issue that we can't set the default the resolution.
        if let Ok(old_connectivity_old) = reg_connectivity_old {
            std::thread::spawn(move || {
                try_reset_resolution_on_first_plug_in(old_connectivity_old.len(), 1920, 1080);
            });
        }

        Ok(())
    }

    fn try_reset_resolution_on_first_plug_in(
        old_connectivity_len: usize,
        width: usize,
        height: usize,
    ) {
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(300));
            if let Ok(reg_connectivity_new) = reg_display_settings::read_reg_connectivity() {
                if reg_connectivity_new.len() != old_connectivity_len {
                    for name in
                        windows::get_device_names(Some(super::AMYUNI_IDD_DEVICE_STRING)).iter()
                    {
                        crate::platform::change_resolution(&name, width, height).ok();
                    }
                    break;
                }
            }
        }
    }

    pub fn plug_in_headless() -> ResultType<()> {
        let mut tm = LAST_PLUG_IN_HEADLESS_TIME.lock().unwrap();
        if let Some(tm) = &mut *tm {
            if tm.elapsed() < Duration::from_secs(3) {
                bail!("Plugging in too frequently.");
            }
        }
        *tm = Some(Instant::now());
        drop(tm);

        let mut is_async = false;
        if let Err(e) = check_install_driver(&mut is_async) {
            log::error!("Failed to install driver: {}", e);
            bail!("Failed to install driver.");
        }

        plug_in_monitor_(true, is_async, Some(Duration::from_millis(3_000)))
    }

    pub fn plug_in_monitor() -> ResultType<()> {
        let mut is_async = false;
        if let Err(e) = check_install_driver(&mut is_async) {
            log::error!("Failed to install driver: {}", e);
            bail!("Failed to install driver.");
        }

        if get_monitor_count() == VIRTUAL_DISPLAY_MAX_COUNT {
            bail!("There are already {VIRTUAL_DISPLAY_MAX_COUNT} monitors plugged in.");
        }

        plug_in_monitor_(true, is_async, None)
    }

    // `index` the display index to plug out. -1 means plug out all.
    // `force_all` is used to forcibly plug out all virtual displays.
    // `force_one` is used to forcibly plug out one virtual display managed by other processes
    //             if there're no virtual displays managed by RustDesk.
    pub fn plug_out_monitor(index: i32, force_all: bool, force_one: bool) -> ResultType<()> {
        let plug_out_all = index == super::IDD_PLUG_OUT_ALL_INDEX;
        // If `plug_out_all and force_all` is true, forcibly plug out all virtual displays.
        // Though the driver may be controlled by other processes,
        // we still forcibly plug out all virtual displays.
        //
        // 1. RustDesk plug in 2 virtual displays. (RustDesk)
        // 2. Other process plug out all virtual displays. (User manually)
        // 3. Other process plug in 1 virtual display. (User manually)
        // 4. RustDesk plug out all virtual displays in this call. (RustDesk disconnect)
        //
        // This is not a normal scenario, RustDesk will plug out virtual display unexpectedly.
        let mut plug_in_count = VIRTUAL_DISPLAY_COUNT.load(atomic::Ordering::Relaxed);
        let amyuni_count = get_monitor_count();
        if !plug_out_all {
            if plug_in_count == 0 && amyuni_count > 0 {
                if force_one {
                    plug_in_count = 1;
                } else {
                    bail!("The virtual display is managed by other processes.");
                }
            }
        } else {
            // Ignore the message if trying to plug out all virtual displays.
        }

        let all_count = windows::get_device_names(None).len();
        let mut to_plug_out_count = match all_count {
            0 => return Ok(()),
            1 => {
                if plug_in_count == 0 {
                    bail!("No virtual displays to plug out.")
                } else {
                    if force_all {
                        1
                    } else {
                        bail!("This only virtual display cannot be plugged out.")
                    }
                }
            }
            _ => {
                if all_count == plug_in_count {
                    if force_all {
                        all_count
                    } else {
                        all_count - 1
                    }
                } else {
                    plug_in_count
                }
            }
        };
        if to_plug_out_count != 0 && !plug_out_all {
            to_plug_out_count = 1;
        }

        for _i in 0..to_plug_out_count {
            let _ = plug_monitor_(false, None);
        }
        Ok(())
    }

    #[inline]
    pub fn get_monitor_count() -> usize {
        windows::get_device_names(Some(super::AMYUNI_IDD_DEVICE_STRING)).len()
    }

    #[inline]
    pub fn is_my_display(name: &str) -> bool {
        windows::get_device_names(Some(super::AMYUNI_IDD_DEVICE_STRING))
            .iter()
            .any(|s| windows::is_device_name(s, name))
    }
}

mod windows {
    use std::ptr::null_mut;
    use winapi::{
        shared::{
            devguid::GUID_DEVCLASS_DISPLAY,
            minwindef::{DWORD, FALSE},
            ntdef::ULONG,
        },
        um::{
            cfgmgr32::{CM_Get_DevNode_Status, CR_SUCCESS},
            cguid::GUID_NULL,
            setupapi::{
                SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiGetDeviceRegistryPropertyW,
                SP_DEVINFO_DATA,
            },
            wingdi::{
                DEVMODEW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ACTIVE, DISPLAY_DEVICE_MIRRORING_DRIVER,
            },
            winnt::HANDLE,
            winuser::{EnumDisplayDevicesW, EnumDisplaySettingsExW, ENUM_CURRENT_SETTINGS},
        },
    };

    const DIGCF_PRESENT: DWORD = 0x00000002;
    const SPDRP_DEVICEDESC: DWORD = 0x00000000;
    const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;

    #[inline]
    pub(super) fn is_device_name(device_name: &str, name: &str) -> bool {
        if name.len() == device_name.len() {
            name == device_name
        } else if name.len() > device_name.len() {
            false
        } else {
            &device_name[..name.len()] == name && device_name.as_bytes()[name.len() as usize] == 0
        }
    }

    pub(super) fn get_device_names(device_string: Option<&str>) -> Vec<String> {
        let mut device_names = Vec::new();
        let mut dd: DISPLAY_DEVICEW = unsafe { std::mem::zeroed() };
        dd.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as DWORD;
        let mut i_dev_num = 0;
        loop {
            let result = unsafe { EnumDisplayDevicesW(null_mut(), i_dev_num, &mut dd, 0) };
            if result == 0 {
                break;
            }
            i_dev_num += 1;

            if 0 == (dd.StateFlags & DISPLAY_DEVICE_ACTIVE)
                || (dd.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) > 0
            {
                continue;
            }

            let mut dm: DEVMODEW = unsafe { std::mem::zeroed() };
            dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
            dm.dmDriverExtra = 0;
            let ok = unsafe {
                EnumDisplaySettingsExW(
                    dd.DeviceName.as_ptr(),
                    ENUM_CURRENT_SETTINGS,
                    &mut dm as _,
                    0,
                )
            };
            if ok == FALSE {
                continue;
            }
            if dm.dmPelsHeight == 0 || dm.dmPelsWidth == 0 {
                continue;
            }

            if let (Ok(device_name), Ok(ds)) = (
                String::from_utf16(&dd.DeviceName),
                String::from_utf16(&dd.DeviceString),
            ) {
                if let Some(s) = device_string {
                    if ds.len() >= s.len() && &ds[..s.len()] == s {
                        device_names.push(device_name);
                    }
                } else {
                    device_names.push(device_name);
                }
            }
        }
        device_names
    }

    pub(super) fn get_display_drivers() -> Vec<(String, u32)> {
        let mut display_drivers: Vec<(String, u32)> = Vec::new();

        let device_info_set = unsafe {
            SetupDiGetClassDevsW(
                &GUID_DEVCLASS_DISPLAY,
                null_mut(),
                null_mut(),
                DIGCF_PRESENT,
            )
        };

        if device_info_set == INVALID_HANDLE_VALUE {
            println!(
                "Failed to get device information set. Error: {}",
                std::io::Error::last_os_error()
            );
            return display_drivers;
        }

        let mut device_info_data = SP_DEVINFO_DATA {
            cbSize: std::mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ClassGuid: GUID_NULL,
            DevInst: 0,
            Reserved: 0,
        };

        let mut device_index = 0;
        loop {
            let result = unsafe {
                SetupDiEnumDeviceInfo(device_info_set, device_index, &mut device_info_data)
            };
            if result == 0 {
                break;
            }

            let mut data_type: DWORD = 0;
            let mut required_size: DWORD = 0;

            // Get the required buffer size for the driver description
            let mut buffer;
            unsafe {
                SetupDiGetDeviceRegistryPropertyW(
                    device_info_set,
                    &mut device_info_data,
                    SPDRP_DEVICEDESC,
                    &mut data_type,
                    null_mut(),
                    0,
                    &mut required_size,
                );

                buffer = vec![0; required_size as usize / 2];
                SetupDiGetDeviceRegistryPropertyW(
                    device_info_set,
                    &mut device_info_data,
                    SPDRP_DEVICEDESC,
                    &mut data_type,
                    buffer.as_mut_ptr() as *mut u8,
                    required_size,
                    null_mut(),
                );
            }

            let Ok(driver_description) = String::from_utf16(&buffer) else {
                println!("Failed to convert driver description to string");
                device_index += 1;
                continue;
            };

            let mut status: ULONG = 0;
            let mut problem_number: ULONG = 0;
            // Get the device status and problem number
            let config_ret = unsafe {
                CM_Get_DevNode_Status(
                    &mut status,
                    &mut problem_number,
                    device_info_data.DevInst,
                    0,
                )
            };
            if config_ret != CR_SUCCESS {
                println!(
                    "Failed to get device status. Error: {}",
                    std::io::Error::last_os_error()
                );
                device_index += 1;
                continue;
            }
            display_drivers.push((driver_description, problem_number));
            device_index += 1;
        }

        display_drivers
    }
}
