#include "pch.h"

#include <Windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <cfgmgr32.h>

#include "./Common.h"

#pragma comment(lib, "SetupAPI.lib")

bool MultiSzContains(LPCWSTR values, LPCWSTR expected)
{
    if (values == NULL || expected == NULL) {
        return false;
    }

    for (LPCWSTR value = values; *value != L'\0'; value += wcslen(value) + 1) {
        if (wcscmp(value, expected) == 0) {
            return true;
        }
    }
    return false;
}

HRESULT UninstallDriver(LPCWSTR hardwareId, DriverUninstallStatus& status, BOOL &rebootRequired)
{
    HRESULT hr = S_OK;
    status = DriverUninstallNotPresent;
    rebootRequired = FALSE;
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to get device information set, last error: %d", lastError);
        return HRESULT_FROM_WIN32(lastError);
    }

    SP_DEVINFO_LIST_DETAIL_DATA devInfoListDetail;
    devInfoListDetail.cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA);
    if (!SetupDiGetDeviceInfoListDetailW(deviceInfoSet, &devInfoListDetail))
    {
        DWORD lastError = GetLastError();
        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        WcaLog(LOGMSG_STANDARD, "Failed to call SetupDiGetDeviceInfoListDetail, last error: %d", lastError);
        return HRESULT_FROM_WIN32(lastError);
    }

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    DWORD dataType;
    DWORD enumError = ERROR_SUCCESS;
    WCHAR deviceId[MAX_DEVICE_ID_LEN] = { 0, };

    DWORD deviceIndex = 0;
    bool found = false;
    while (SetupDiEnumDeviceInfo(deviceInfoSet, deviceIndex, &deviceInfoData))
    {
        ZeroMemory(deviceId, sizeof(deviceId));
        if (!SetupDiGetDeviceRegistryPropertyW(deviceInfoSet, &deviceInfoData, SPDRP_HARDWAREID, &dataType, (PBYTE)deviceId, sizeof(deviceId), NULL))
        {
            DWORD lastError = GetLastError();
            WcaLog(LOGMSG_STANDARD, "Failed to get hardware id, last error: %d", lastError);
            hr = HRESULT_FROM_WIN32(lastError);
            goto Cleanup;
        }
        if (!MultiSzContains(deviceId, hardwareId))
        {
            deviceIndex++;
            continue;
        }
        found = true;

        SP_REMOVEDEVICE_PARAMS remove_device_params;
        remove_device_params.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        remove_device_params.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        remove_device_params.Scope = DI_REMOVEDEVICE_GLOBAL;
        remove_device_params.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(deviceInfoSet, &deviceInfoData, &remove_device_params.ClassInstallHeader, sizeof(SP_REMOVEDEVICE_PARAMS)))
        {
            DWORD lastError = GetLastError();
            WcaLog(LOGMSG_STANDARD, "Failed to set class install params, last error: %d", lastError);
            hr = HRESULT_FROM_WIN32(lastError);
            goto Cleanup;
        }

        if (!SetupDiCallClassInstaller(DIF_REMOVE, deviceInfoSet, &deviceInfoData))
        {
            DWORD lastError = GetLastError();
            WcaLog(LOGMSG_STANDARD, "Failed to uninstall driver, last error: %d", lastError);
            hr = HRESULT_FROM_WIN32(lastError);
            goto Cleanup;
        }

        SP_DEVINSTALL_PARAMS deviceParams;
        deviceParams.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
        if (SetupDiGetDeviceInstallParamsW(deviceInfoSet, &deviceInfoData, &deviceParams))
        {
            if (deviceParams.Flags & (DI_NEEDRESTART | DI_NEEDREBOOT))
            {
                rebootRequired = true;
            }
        }

        WcaLog(LOGMSG_STANDARD, "Driver uninstalled successfully");
        status = DriverUninstallRemoved;
        deviceIndex++;
    }
    enumError = GetLastError();
    if (enumError != ERROR_NO_MORE_ITEMS)
    {
        WcaLog(LOGMSG_STANDARD, "Failed to enumerate display devices, last error: %d", enumError);
        hr = HRESULT_FROM_WIN32(enumError);
        goto Cleanup;
    }

    if (!found)
    {
        WcaLog(LOGMSG_STANDARD, "Driver hardware id \"%ls\" is not present", hardwareId);
    }

Cleanup:
    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return hr;
}
