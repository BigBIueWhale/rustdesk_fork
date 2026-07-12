// CustomAction.cpp : Defines the entry point for the custom action.
#include "pch.h"
#include <stdlib.h>
#include <strutil.h>
#include <shlwapi.h>
#include <shlobj.h>

#include "./Common.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Shell32.lib")

HRESULT NormalizeMsiPath(LPCWSTR path, LPWSTR normalized, size_t normalizedCch, LPCWSTR label, BOOL trimTrailingSlashes)
{
    if (path == NULL || path[0] == L'\0')
    {
        WcaLog(LOGMSG_STANDARD, "%ls is empty.", label);
        return E_INVALIDARG;
    }
    if (PathIsRelativeW(path))
    {
        WcaLog(LOGMSG_STANDARD, "%ls is relative: '%ls'.", label, path);
        return E_INVALIDARG;
    }

    DWORD length = GetFullPathNameW(path, static_cast<DWORD>(normalizedCch), normalized, NULL);
    if (length == 0)
    {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to normalize %ls '%ls'. Error: %lu", label, path, lastError);
        return HRESULT_FROM_WIN32(lastError);
    }
    if (length >= normalizedCch)
    {
        WcaLog(LOGMSG_STANDARD, "%ls is too long: '%ls'.", label, path);
        return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    }

    while (trimTrailingSlashes && !PathIsRootW(normalized))
    {
        size_t normalizedLen = 0;
        HRESULT hr = StringCchLengthW(normalized, normalizedCch, &normalizedLen);
        if (FAILED(hr) || normalizedLen == 0)
        {
            return FAILED(hr) ? hr : E_INVALIDARG;
        }
        WCHAR last = normalized[normalizedLen - 1];
        if (last != L'\\' && last != L'/')
        {
            break;
        }
        normalized[normalizedLen - 1] = L'\0';
    }

    return S_OK;
}

HRESULT NormalizeMsiDirectoryPath(LPCWSTR path, LPWSTR normalized, size_t normalizedCch, LPCWSTR label)
{
    return NormalizeMsiPath(path, normalized, normalizedCch, label, TRUE);
}


BOOL PathsEqualNoCase(LPCWSTR a, LPCWSTR b)
{
    return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL;
}

BOOL KnownFolderMatchesPath(REFKNOWNFOLDERID folder, LPCWSTR path)
{
    PWSTR rawKnownPath = NULL;
    HRESULT hr = SHGetKnownFolderPath(folder, KF_FLAG_DEFAULT, NULL, &rawKnownPath);
    if (FAILED(hr))
    {
        WcaLog(LOGMSG_STANDARD, "Failed to resolve trusted MSI known folder: 0x%08lx", hr);
        return FALSE;
    }

    WCHAR knownPath[MAX_PATH] = { 0 };
    hr = NormalizeMsiDirectoryPath(rawKnownPath, knownPath, MAX_PATH, L"trusted MSI known folder");
    CoTaskMemFree(rawKnownPath);
    if (FAILED(hr))
    {
        return FALSE;
    }

    return PathsEqualNoCase(path, knownPath);
}

HRESULT RequireExistingMsiDirectoryNoReparse(LPCWSTR path, LPCWSTR label)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "%ls '%ls' is not accessible. Error: %lu", label, path, lastError);
        return HRESULT_FROM_WIN32(lastError);
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        WcaLog(LOGMSG_STANDARD, "%ls '%ls' is not a directory.", label, path);
        return E_INVALIDARG;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        WcaLog(LOGMSG_STANDARD, "%ls '%ls' is a reparse point.", label, path);
        return E_INVALIDARG;
    }
    return S_OK;
}

HRESULT ValidateDeferredInstallFolder(LPCWSTR installFolder, LPWSTR normalizedInstallFolder, size_t normalizedCch)
{
    HRESULT hr = NormalizeMsiDirectoryPath(installFolder, normalizedInstallFolder, normalizedCch, L"MSI install folder");
    if (FAILED(hr))
    {
        return hr;
    }

    WCHAR parent[MAX_PATH] = { 0 };
    hr = StringCchCopyW(parent, MAX_PATH, normalizedInstallFolder);
    if (FAILED(hr))
    {
        return hr;
    }
    if (!PathRemoveFileSpecW(parent))
    {
        WcaLog(LOGMSG_STANDARD, "MSI install folder has no parent: '%ls'.", normalizedInstallFolder);
        return E_INVALIDARG;
    }
    WCHAR normalizedParent[MAX_PATH] = { 0 };
    hr = NormalizeMsiDirectoryPath(parent, normalizedParent, MAX_PATH, L"MSI install folder parent");
    if (FAILED(hr))
    {
        return hr;
    }

    if (!KnownFolderMatchesPath(FOLDERID_ProgramFiles, normalizedParent) &&
        !KnownFolderMatchesPath(FOLDERID_ProgramFilesX86, normalizedParent))
    {
        WcaLog(LOGMSG_STANDARD, "MSI install folder is not an immediate Program Files child: '%ls'.", normalizedInstallFolder);
        return E_INVALIDARG;
    }
    hr = RequireExistingMsiDirectoryNoReparse(normalizedParent, L"MSI install folder parent");
    if (FAILED(hr))
    {
        return hr;
    }

    DWORD attributes = GetFileAttributesW(normalizedInstallFolder);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
        {
            return S_OK;
        }
        WcaLog(LOGMSG_STANDARD, "MSI install folder cannot be inspected: '%ls'. Error: %lu", normalizedInstallFolder, lastError);
        return HRESULT_FROM_WIN32(lastError);
    }
    if (!(attributes & FILE_ATTRIBUTE_DIRECTORY))
    {
        WcaLog(LOGMSG_STANDARD, "MSI install folder is not a directory: '%ls'.", normalizedInstallFolder);
        return E_INVALIDARG;
    }
    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
    {
        WcaLog(LOGMSG_STANDARD, "MSI install folder is a reparse point: '%ls'.", normalizedInstallFolder);
        return E_INVALIDARG;
    }

    return S_OK;
}


// Helper function to safely delete a file using handle-based deletion.
// Directories are refused after opening the handle.
BOOL SafeDeleteItem(LPCWSTR fullPath)
{
    // Open the file/directory with delete and attribute-read access plus FILE_FLAG_OPEN_REPARSE_POINT
    // to prevent following symlinks.
    // Use shared access to allow deletion even when other processes have the file open.
    DWORD flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    HANDLE hFile = CreateFileW(
        fullPath,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,  // Allow shared access
        NULL,
        OPEN_EXISTING,
        flags,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE)
    {
        WcaLog(LOGMSG_STANDARD, "SafeDeleteItem: Failed to open '%ls'. Error: %lu", fullPath, GetLastError());
        return FALSE;
    }

    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (FALSE == GetFileInformationByHandle(hFile, &fileInfo))
    {
        WcaLog(LOGMSG_STANDARD, "SafeDeleteItem: Failed to inspect '%ls'. Error: %lu", fullPath, GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    if (fileInfo.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        WcaLog(LOGMSG_STANDARD, "SafeDeleteItem: Refusing to delete directory '%ls'.", fullPath);
        CloseHandle(hFile);
        return FALSE;
    }

    // Use SetFileInformationByHandle to mark for deletion.
    // The file will be deleted when the handle is closed.
    FILE_DISPOSITION_INFO dispInfo;
    dispInfo.DeleteFile = TRUE;

    BOOL result = SetFileInformationByHandle(
        hFile,
        FileDispositionInfo,
        &dispInfo,
        sizeof(dispInfo)
    );

    if (!result)
    {
        DWORD error = GetLastError();
        WcaLog(LOGMSG_STANDARD, "SafeDeleteItem: Failed to mark '%ls' for deletion. Error: %lu", fullPath, error);
    }

    CloseHandle(hFile);
    return result;
}

BOOL PathEndsWithSlash(LPCWSTR path)
{
    size_t length = 0;
    HRESULT hr = StringCchLengthW(path, MAX_PATH, &length);
    if (FAILED(hr) || length == 0)
    {
        return FALSE;
    }

    WCHAR last = path[length - 1];
    return last == L'\\' || last == L'/';
}

void ClearReadOnlyAttribute(LPCWSTR fullPath, DWORD attributes)
{
    if (!(attributes & FILE_ATTRIBUTE_READONLY))
    {
        return;
    }

    DWORD writableAttributes = attributes & ~FILE_ATTRIBUTE_READONLY;
    if (writableAttributes == 0)
    {
        writableAttributes = FILE_ATTRIBUTE_NORMAL;
    }

    if (SetFileAttributesW(fullPath, writableAttributes))
    {
        WcaLog(LOGMSG_STANDARD, "Runtime cleanup cleared read-only attribute for '%ls'.", fullPath);
        return;
    }

    WcaLog(LOGMSG_STANDARD, "Runtime cleanup failed to clear read-only attribute for '%ls'. Error: %lu", fullPath, GetLastError());
}

BOOL DeleteRuntimeGeneratedFile(LPCWSTR installFolder, LPCWSTR fileName)
{
    WCHAR fullPath[MAX_PATH];
    LPCWSTR separator = PathEndsWithSlash(installFolder) ? L"" : L"\\";
    HRESULT hr = StringCchPrintfW(fullPath, MAX_PATH, L"%s%s%s", installFolder, separator, fileName);
    if (FAILED(hr))
    {
        WcaLog(LOGMSG_STANDARD, "Runtime cleanup path is too long for '%ls'.", fileName);
        return FALSE;
    }

    DWORD attributes = GetFileAttributesW(fullPath);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
        {
            return TRUE;
        }

        WcaLog(LOGMSG_STANDARD, "Runtime cleanup cannot stat '%ls'. Error: %lu", fullPath, error);
        return FALSE;
    }

    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        WcaLog(LOGMSG_STANDARD, "Runtime cleanup skipped directory '%ls'.", fullPath);
        return FALSE;
    }

    ClearReadOnlyAttribute(fullPath, attributes);
    WcaLog(LOGMSG_STANDARD, "Runtime cleanup deleting '%ls'.", fullPath);
    return SafeDeleteItem(fullPath);
}

// See `Package.wxs` for the sequence of this custom action.
//
UINT __stdcall RemoveRuntimeGeneratedFiles(
    __in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    LPWSTR installFolder = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzData = NULL;
    WCHAR normalizedInstallFolder[MAX_PATH] = { 0 };

    hr = WcaInitialize(hInstall, "RemoveRuntimeGeneratedFiles");
    ExitOnFailure(hr, "Failed to initialize");

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &installFolder);
    ExitOnFailure(hr, "failed to read install folder from custom action data: %ls", pwz);

    hr = ValidateDeferredInstallFolder(installFolder, normalizedInstallFolder, MAX_PATH);
    ExitOnFailure(hr, "Runtime cleanup install folder is not trusted");

    WcaLog(LOGMSG_STANDARD, "Removing runtime-generated files from install folder: %ls", normalizedInstallFolder);
    if (!DeleteRuntimeGeneratedFile(normalizedInstallFolder, L"RuntimeBroker_rustdesk.exe"))
    {
        hr = E_FAIL;
        ExitOnFailure(hr, "Failed to remove runtime-generated broker executable");
    }
    WcaLog(LOGMSG_STANDARD, "Runtime-generated file cleanup completed.");

LExit:
    ReleaseStr(pwzData);

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}

UINT __stdcall RemoveTestCertificates(__in MSIHANDLE hInstall)
{
    HRESULT hr = WcaInitialize(hInstall, "RemoveTestCertificates");
    if (SUCCEEDED(hr) && !DeleteRustDeskTestCertsW())
    {
        hr = E_FAIL;
    }
    return WcaFinalize(SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE);
}

UINT __stdcall RemoveAmyuniIdd(
    __in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;
    BOOL rebootRequired = FALSE;
    DriverUninstallStatus uninstallStatus = DriverUninstallNotPresent;

    hr = WcaInitialize(hInstall, "RemoveAmyuniIdd");
    ExitOnFailure(hr, "Failed to initialize");

    hr = UninstallDriver(L"usbmmidd", uninstallStatus, rebootRequired);
    ExitOnFailure(hr, "SetupAPI Amyuni IDD removal failed");
    if (uninstallStatus == DriverUninstallNotPresent) {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD device is not present");
    } else {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD device removed through SetupAPI");
    }

LExit:
    if (rebootRequired && SUCCEEDED(hr)) {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD removal requires reboot");
        HRESULT rebootHr = WcaDeferredActionRequiresReboot();
        if (FAILED(rebootHr)) {
            WcaLog(LOGMSG_STANDARD, "Failed to signal Amyuni IDD reboot requirement: 0x%08lx", rebootHr);
            hr = rebootHr;
        }
    }
    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}
