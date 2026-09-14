use super::{
    PrivacyMode, PrivacyModeConnectionOwner, PrivacyModeState, NO_PHYSICAL_DISPLAYS,
};
use crate::virtual_display_manager::MonitorMode;
use crate::{platform::windows::reg_display_settings, virtual_display_manager};
use hbb_common::{allow_err, bail, log, ResultType};
use std::{
    io::Error,
    ops::{Deref, DerefMut},
    thread,
    time::Duration,
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE},
        ntdef::{NULL, WCHAR},
    },
    um::{
        wingdi::{
            DEVMODEW, DISPLAY_DEVICEW, DISPLAY_DEVICE_ACTIVE, DISPLAY_DEVICE_ATTACHED_TO_DESKTOP,
            DISPLAY_DEVICE_MIRRORING_DRIVER, DISPLAY_DEVICE_PRIMARY_DEVICE, DM_POSITION,
        },
        winuser::{
            ChangeDisplaySettingsExW, EnumDisplayDevicesW, EnumDisplaySettingsExW,
            EnumDisplaySettingsW, CDS_NORESET, CDS_RESET, CDS_SET_PRIMARY, CDS_UPDATEREGISTRY,
            DISP_CHANGE_FAILED, DISP_CHANGE_SUCCESSFUL, EDD_GET_DEVICE_INTERFACE_NAME,
            ENUM_CURRENT_SETTINGS, ENUM_REGISTRY_SETTINGS,
        },
    },
};

pub(super) const PRIVACY_MODE_IMPL: &str = super::PRIVACY_MODE_IMPL_WIN_VIRTUAL_DISPLAY;

struct Display {
    dm: DEVMODEW,
    name: [WCHAR; 32],
    primary: bool,
}

pub struct PrivacyModeImpl {
    impl_key: String,
    owner: Option<PrivacyModeConnectionOwner>,
    displays: Vec<Display>,
    virtual_displays: Vec<Display>,
    created_virtual_display_count: usize,
    reg_recoveries: Vec<reg_display_settings::RegRecovery>,
}

struct TurnOnGuard<'a> {
    privacy_mode: &'a mut PrivacyModeImpl,
    owner: Option<PrivacyModeConnectionOwner>,
    succeeded: bool,
}

impl<'a> Deref for TurnOnGuard<'a> {
    type Target = PrivacyModeImpl;

    fn deref(&self) -> &Self::Target {
        self.privacy_mode
    }
}

impl<'a> DerefMut for TurnOnGuard<'a> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.privacy_mode
    }
}

impl<'a> Drop for TurnOnGuard<'a> {
    fn drop(&mut self) {
        if !self.succeeded {
            if let Err(error) = self.rollback() {
                log::error!("Failed to roll back incomplete virtual-display privacy mode: {error}");
            }
        }
    }
}

impl TurnOnGuard<'_> {
    fn ensure_activation_current(&self) -> ResultType<()> {
        let Some(owner) = self.owner.as_ref() else {
            bail!("privacy activation lost its exact pending owner");
        };
        owner.ensure_activation_current()
    }

    fn rollback(&mut self) -> ResultType<()> {
        let result = self.privacy_mode.turn_off_privacy(None);
        if result.is_err() && self.privacy_mode.owner.is_none() {
            self.privacy_mode.owner = self.owner.take();
        }
        self.succeeded = true;
        result
    }
}

impl PrivacyModeImpl {
    pub fn new(impl_key: &str) -> Self {
        Self {
            impl_key: impl_key.to_owned(),
            owner: None,
            displays: Vec::new(),
            virtual_displays: Vec::new(),
            created_virtual_display_count: 0,
            reg_recoveries: Vec::new(),
        }
    }

    // mainly from https://github.com/rustdesk-org/rustdesk/blob/44c3a52ca8502cf53b58b59db130611778d34dbe/libs/scrap/src/dxgi/mod.rs#L365
    fn set_displays(&mut self) {
        self.displays.clear();
        self.virtual_displays.clear();

        let mut i: DWORD = 0;
        loop {
            #[allow(invalid_value)]
            let mut dd: DISPLAY_DEVICEW = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            dd.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as _;
            let ok = unsafe { EnumDisplayDevicesW(std::ptr::null(), i, &mut dd as _, 0) };
            if ok == FALSE {
                break;
            }
            i += 1;
            if 0 == (dd.StateFlags & DISPLAY_DEVICE_ACTIVE)
                || (dd.StateFlags & DISPLAY_DEVICE_MIRRORING_DRIVER) > 0
            {
                continue;
            }
            #[allow(invalid_value)]
            let mut dm: DEVMODEW = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
            dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
            dm.dmDriverExtra = 0;
            unsafe {
                if FALSE
                    == EnumDisplaySettingsExW(
                        dd.DeviceName.as_ptr(),
                        ENUM_CURRENT_SETTINGS,
                        &mut dm as _,
                        0,
                    )
                {
                    if FALSE
                        == EnumDisplaySettingsExW(
                            dd.DeviceName.as_ptr(),
                            ENUM_REGISTRY_SETTINGS,
                            &mut dm as _,
                            0,
                        )
                    {
                        continue;
                    }
                }
            }

            let primary = (dd.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE) > 0;
            let display = Display {
                dm,
                name: dd.DeviceName,
                primary,
            };

            let ds = virtual_display_manager::get_cur_device_string();
            if let Ok(s) = String::from_utf16(&dd.DeviceString) {
                if s.len() >= ds.len() && &s[..ds.len()] == ds {
                    self.virtual_displays.push(display);
                    continue;
                }
            }
            self.displays.push(display);
        }
    }

    fn restore_plug_out_monitor(&mut self) -> ResultType<()> {
        virtual_display_manager::plug_out_monitor_count(
            self.created_virtual_display_count,
            true,
            false,
        )?;
        self.created_virtual_display_count = 0;
        Ok(())
    }

    #[inline]
    fn change_display_settings_ex_err_msg(rc: i32) -> String {
        if rc != DISP_CHANGE_FAILED {
            format!("ret: {}", rc)
        } else {
            format!(
                "ret: {}, last error: {:?}",
                rc,
                std::io::Error::last_os_error()
            )
        }
    }

    fn set_primary_display(&mut self) -> ResultType<String> {
        // Multiple virtual displays with different origins are tested.
        let display = &self.virtual_displays[0];
        let display_name = std::string::String::from_utf16(&display.name)?;

        #[allow(invalid_value)]
        let mut new_primary_dm: DEVMODEW = unsafe { std::mem::MaybeUninit::uninit().assume_init() };
        new_primary_dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
        new_primary_dm.dmDriverExtra = 0;
        unsafe {
            if FALSE
                == EnumDisplaySettingsW(
                    display.name.as_ptr(),
                    ENUM_CURRENT_SETTINGS,
                    &mut new_primary_dm,
                )
            {
                bail!(
                    "Failed EnumDisplaySettingsW, device name: {:?}, error: {}",
                    std::string::String::from_utf16(&display.name),
                    Error::last_os_error()
                );
            }

            // Windows 24H2 requires the virtual display to be set first.
            // No idea why, maybe the same issue: https://developercommunity.visualstudio.com/t/Windows-11-Enterprise-24H2-using-WinApi/10851936?sort=newest
            let flags = CDS_UPDATEREGISTRY | CDS_NORESET;
            let offx = new_primary_dm.u1.s2().dmPosition.x;
            let offy = new_primary_dm.u1.s2().dmPosition.y;
            new_primary_dm.u1.s2_mut().dmPosition.x = 0;
            new_primary_dm.u1.s2_mut().dmPosition.y = 0;
            new_primary_dm.dmFields |= DM_POSITION;
            let rc = ChangeDisplaySettingsExW(
                display.name.as_ptr(),
                &mut new_primary_dm,
                NULL as _,
                flags | CDS_SET_PRIMARY,
                NULL,
            );
            if rc != DISP_CHANGE_SUCCESSFUL {
                let err = Self::change_display_settings_ex_err_msg(rc);
                log::error!(
                    "Failed ChangeDisplaySettingsEx, the virtual display, {}",
                    &err
                );
                bail!("Failed ChangeDisplaySettingsEx, {}", err);
            }

            let mut i: DWORD = 0;
            loop {
                #[allow(invalid_value)]
                let mut dd: DISPLAY_DEVICEW = std::mem::MaybeUninit::uninit().assume_init();
                dd.cb = std::mem::size_of::<DISPLAY_DEVICEW>() as _;
                if FALSE
                    == EnumDisplayDevicesW(NULL as _, i, &mut dd, EDD_GET_DEVICE_INTERFACE_NAME)
                {
                    break;
                }
                i += 1;
                if (dd.StateFlags & DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) == 0 {
                    continue;
                }
                // Skip the virtual display.
                if dd.DeviceName == display.name {
                    continue;
                }

                #[allow(invalid_value)]
                let mut dm: DEVMODEW = std::mem::MaybeUninit::uninit().assume_init();
                dm.dmSize = std::mem::size_of::<DEVMODEW>() as _;
                dm.dmDriverExtra = 0;
                if FALSE
                    == EnumDisplaySettingsW(dd.DeviceName.as_ptr(), ENUM_CURRENT_SETTINGS, &mut dm)
                {
                    bail!(
                        "Failed EnumDisplaySettingsW, device name: {:?}, error: {}",
                        std::string::String::from_utf16(&dd.DeviceName),
                        Error::last_os_error()
                    );
                }

                dm.u1.s2_mut().dmPosition.x -= offx;
                dm.u1.s2_mut().dmPosition.y -= offy;
                dm.dmFields |= DM_POSITION;
                let rc = ChangeDisplaySettingsExW(
                    dd.DeviceName.as_ptr(),
                    &mut dm,
                    NULL as _,
                    flags,
                    NULL,
                );
                if rc != DISP_CHANGE_SUCCESSFUL {
                    let err = Self::change_display_settings_ex_err_msg(rc);
                    log::error!(
                        "Failed ChangeDisplaySettingsEx, device name: {:?}, flags: {}, {}",
                        std::string::String::from_utf16(&dd.DeviceName),
                        flags,
                        &err
                    );
                    bail!("Failed ChangeDisplaySettingsEx, {}", err);
                }

                // If we want to set dpi, the following references may be helpful.
                // And setting dpi should be called after changing the display settings.
                // https://stackoverflow.com/questions/35233182/how-can-i-change-windows-10-display-scaling-programmatically-using-c-sharp
                // https://github.com/lihas/windows-DPI-scaling-sample/blob/master/DPIHelper/DpiHelper.cpp
                //
                // But the official API does not provide a way to get/set dpi.
                // https://learn.microsoft.com/en-us/windows/win32/api/wingdi/ne-wingdi-displayconfig_device_info_type
                // https://github.com/lihas/windows-DPI-scaling-sample/blob/738ac18b7a7ce2d8fdc157eb825de9cb5eee0448/DPIHelper/DpiHelper.h#L37
            }
        }

        Ok(display_name)
    }

    // NOTE: We can't detect if the other virtual displays are physical displays or not.
    // We can only use `DeviceString` == `virtual_display_manager::get_cur_device_string()` to detect if the display is a virtual display.
    // The other virtual displays can't be restored after exiting the privacy mode on Windows 24H2.
    fn disable_physical_displays(&self) -> ResultType<()> {
        for display in &self.displays {
            let mut dm = display.dm.clone();
            unsafe {
                dm.u1.s2_mut().dmPosition.x = 10000;
                dm.u1.s2_mut().dmPosition.y = 10000;
                dm.dmPelsHeight = 0;
                dm.dmPelsWidth = 0;
                let flags = CDS_UPDATEREGISTRY | CDS_NORESET;
                let rc = ChangeDisplaySettingsExW(
                    display.name.as_ptr(),
                    &mut dm,
                    NULL as _,
                    flags,
                    NULL as _,
                );
                if rc != DISP_CHANGE_SUCCESSFUL {
                    let err = Self::change_display_settings_ex_err_msg(rc);
                    log::error!(
                        "Failed ChangeDisplaySettingsEx, device name: {:?}, flags: {}, {}",
                        std::string::String::from_utf16(&display.name),
                        flags,
                        &err
                    );
                    bail!("Failed ChangeDisplaySettingsEx, {}", err);
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn default_display_modes() -> Vec<MonitorMode> {
        vec![MonitorMode {
            width: 1920,
            height: 1080,
            sync: 60,
        }]
    }

    // After the bounded plug-in/resolution operation, the owned privacy-activation worker may wait
    // up to six additional seconds for the Amyuni display to appear. This blocking readiness path
    // never runs on a Tokio worker thread.
    pub fn ensure_virtual_display(&mut self, wait_for_driver: bool) -> ResultType<()> {
        if self.virtual_displays.is_empty() {
            let created_count =
                virtual_display_manager::plug_in_peer_request(vec![Self::default_display_modes()])?;
            self.created_virtual_display_count = self
                .created_virtual_display_count
                .checked_add(created_count)
                .ok_or_else(|| {
                    hbb_common::anyhow::anyhow!("virtual display creation count overflow")
                })?;
            if wait_for_driver {
                thread::sleep(Duration::from_secs(1));
            }
            self.set_displays();
            // No physical displays, no need to use the privacy mode.
            if self.displays.is_empty() {
                self.restore_plug_out_monitor()?;
                self.virtual_displays.clear();
                bail!(NO_PHYSICAL_DISPLAYS);
            }

            if wait_for_driver {
                let now = std::time::Instant::now();
                while self.virtual_displays.is_empty()
                    && now.elapsed() < Duration::from_millis(5000)
                {
                    thread::sleep(Duration::from_millis(500));
                    self.set_displays();
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn commit_change_display(flags: DWORD) -> ResultType<()> {
        unsafe {
            // use winapi::{
            //     shared::windef::HDESK,
            //     um::{
            //         processthreadsapi::GetCurrentThreadId,
            //         winnt::MAXIMUM_ALLOWED,
            //         winuser::{CloseDesktop, GetThreadDesktop, OpenInputDesktop, SetThreadDesktop},
            //     },
            // };
            // let mut desk_input: HDESK = NULL as _;
            // let desk_current: HDESK = GetThreadDesktop(GetCurrentThreadId());
            // if !desk_current.is_null() {
            //     desk_input = OpenInputDesktop(0, FALSE, MAXIMUM_ALLOWED);
            //     if desk_input.is_null() {
            //         SetThreadDesktop(desk_input);
            //     }
            // }

            let rc = ChangeDisplaySettingsExW(NULL as _, NULL as _, NULL as _, flags, NULL as _);
            if rc != DISP_CHANGE_SUCCESSFUL {
                let err = Self::change_display_settings_ex_err_msg(rc);
                bail!("Failed ChangeDisplaySettingsEx, {}", err);
            }

            // if !desk_current.is_null() {
            //     SetThreadDesktop(desk_current);
            // }
            // if !desk_input.is_null() {
            //     CloseDesktop(desk_input);
            // }
        }
        Ok(())
    }

    fn restore(&mut self) -> ResultType<()> {
        if self.displays.is_empty()
            && self.virtual_displays.is_empty()
            && self.created_virtual_display_count == 0
        {
            return Ok(());
        }

        Self::restore_displays(&self.displays)?;
        Self::restore_displays(&self.virtual_displays)?;
        Self::commit_change_display(0)?;
        if self.created_virtual_display_count != 0 {
            self.restore_plug_out_monitor()?;
        }
        self.displays.clear();
        self.virtual_displays.clear();
        self.created_virtual_display_count = 0;
        Ok(())
    }

    fn restore_displays(displays: &[Display]) -> ResultType<()> {
        let mut failures = Vec::new();
        for display in displays {
            unsafe {
                let mut dm = display.dm.clone();
                let flags = if display.primary {
                    CDS_NORESET | CDS_UPDATEREGISTRY | CDS_SET_PRIMARY
                } else {
                    CDS_NORESET | CDS_UPDATEREGISTRY
                };
                let rc = ChangeDisplaySettingsExW(
                    display.name.as_ptr(),
                    &mut dm,
                    std::ptr::null_mut(),
                    flags,
                    std::ptr::null_mut(),
                );
                if rc != DISP_CHANGE_SUCCESSFUL {
                    failures.push(format!(
                        "device {:?}: {}",
                        String::from_utf16_lossy(&display.name),
                        Self::change_display_settings_ex_err_msg(rc),
                    ));
                }
            }
        }
        if !failures.is_empty() {
            bail!(
                "Failed to stage restored display settings: {}",
                failures.join("; ")
            );
        }
        Ok(())
    }
}

impl PrivacyMode for PrivacyModeImpl {
    fn clear(&mut self) -> ResultType<()> {
        self.turn_off_privacy(None)
    }

    fn turn_on_privacy(&mut self, owner: PrivacyModeConnectionOwner) -> ResultType<bool> {
        let conn_id = owner.conn_id();
        if !virtual_display_manager::is_virtual_display_supported() {
            bail!("idd_not_support_under_win10_2004_tip");
        }

        if self.check_on_owner(&owner)? {
            log::debug!("Privacy mode of conn {} is already on", conn_id);
            return Ok(true);
        }
        self.set_displays();
        if self.displays.is_empty() {
            log::debug!("{}", NO_PHYSICAL_DISPLAYS);
            bail!(NO_PHYSICAL_DISPLAYS);
        }

        owner.ensure_activation_current()?;
        let waits_for_driver = virtual_display_manager::is_amyuni_idd();
        let mut guard = TurnOnGuard {
            privacy_mode: self,
            owner: Some(owner),
            succeeded: false,
        };

        guard.ensure_virtual_display(waits_for_driver)?;
        guard.ensure_activation_current()?;
        if guard.virtual_displays.is_empty() {
            log::debug!("No virtual displays");
            bail!("No virtual displays.");
        }

        let reg_connectivity_1 = reg_display_settings::read_reg_connectivity()?;
        let primary_display_name = guard.set_primary_display()?;
        guard.ensure_activation_current()?;
        guard.disable_physical_displays()?;
        guard.ensure_activation_current()?;
        Self::commit_change_display(CDS_RESET)?;
        guard.ensure_activation_current()?;
        // Explicitly set the resolution(virtual display) to 1920x1080.
        allow_err!(crate::platform::change_resolution(
            &primary_display_name,
            1920,
            1080
        ));
        guard.ensure_activation_current()?;
        let reg_connectivity_2 = reg_display_settings::read_reg_connectivity()?;

        guard.reg_recoveries =
            reg_display_settings::diff_recent_connectivity(reg_connectivity_1, reg_connectivity_2)?;

        guard.ensure_activation_current()?;
        let Some(owner) = guard.owner.as_ref() else {
            bail!("privacy activation lost its exact pending owner");
        };
        super::win_privacy_hotkey::register_escape_hotkey(owner)?;
        guard.ensure_activation_current()?;
        let Some(owner) = guard.owner.as_mut() else {
            bail!("privacy activation lost its exact pending owner");
        };
        if let Err(activation_error) = owner.commit_activation() {
            let rollback = guard.rollback();
            return match rollback {
                Ok(()) => Err(activation_error),
                Err(rollback_error) => Err(hbb_common::anyhow::anyhow!(
                    "{activation_error}; failed to roll back cancelled virtual-display privacy activation: {rollback_error}"
                )),
            };
        }
        let Some(owner) = guard.owner.take() else {
            bail!("privacy activation lost its exact committed owner");
        };
        guard.privacy_mode.owner = Some(owner);
        guard.succeeded = true;

        Ok(true)
    }

    fn turn_off_privacy(&mut self, state: Option<PrivacyModeState>) -> ResultType<()> {
        let mut failures = Vec::new();
        if let Err(error) = super::win_privacy_hotkey::unregister_escape_hotkey() {
            failures.push(format!("failed to stop privacy escape hotkey: {error}"));
        }
        let _tmp_ignore_changed_holder = crate::display_service::temp_ignore_displays_changed();
        if let Err(error) = self.restore() {
            failures.push(format!("failed to restore privacy displays: {error}"));
        }
        // We need to force restore the registry connectivity.
        // This is because the registry connection may be changed by `self.restore()`, but will not be fully restored.
        if !self.reg_recoveries.is_empty() {
            match reg_display_settings::restore_reg_connectivity(&self.reg_recoveries) {
                Ok(()) => self.reg_recoveries.clear(),
                Err(error) => failures.push(format!(
                    "failed to restore privacy display registry connectivity: {error}"
                )),
            }
        }

        if failures.is_empty() {
            if let Some(owner) = self.owner.take() {
                if let Some(state) = state {
                    allow_err!(super::set_privacy_mode_state(
                        &owner,
                        state,
                        PRIVACY_MODE_IMPL.to_string(),
                        1_000
                    ));
                }
            }
            Ok(())
        } else {
            bail!("Privacy teardown incomplete: {}", failures.join("; "))
        }
    }

    #[inline]
    fn connection_owner(&self) -> Option<&PrivacyModeConnectionOwner> {
        self.owner.as_ref()
    }

    #[inline]
    fn get_impl_key(&self) -> &str {
        &self.impl_key
    }
}

impl Drop for PrivacyModeImpl {
    fn drop(&mut self) {
        if self.owner.is_some() {
            allow_err!(self.turn_off_privacy(None));
        }
    }
}
