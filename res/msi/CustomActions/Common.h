#pragma once

#include <Windows.h>

extern "C" BOOL DeleteRustDeskTestCertsW();

enum DriverUninstallStatus {
    DriverUninstallNotPresent,
    DriverUninstallRemoved,
};

HRESULT UninstallDriver(LPCWSTR hardwareId, DriverUninstallStatus& status, BOOL &rebootRequired);
