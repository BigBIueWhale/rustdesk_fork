#pragma once

#include <Windows.h>

enum DriverUninstallStatus {
    DriverUninstallNotPresent,
    DriverUninstallRemoved,
};

HRESULT UninstallDriver(LPCWSTR hardwareId, DriverUninstallStatus& status, BOOL &rebootRequired);
