// CustomAction.cpp : Defines the entry point for the custom action.
#include "pch.h"
#include <stdlib.h>
#include <strutil.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <netfw.h>
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

HRESULT NormalizeMsiFilePath(LPCWSTR path, LPWSTR normalized, size_t normalizedCch, LPCWSTR label)
{
    HRESULT hr = NormalizeMsiPath(path, normalized, normalizedCch, label, FALSE);
    if (FAILED(hr))
    {
        return hr;
    }
    if (PathIsRootW(normalized))
    {
        WcaLog(LOGMSG_STANDARD, "%ls is a filesystem root: '%ls'.", label, normalized);
        return E_INVALIDARG;
    }
    return S_OK;
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

HRESULT RequireExistingMsiFileNoReparse(LPCWSTR path, LPCWSTR label)
{
    DWORD attributes = GetFileAttributesW(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
    {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "%ls '%ls' is not accessible. Error: %lu", label, path, lastError);
        return HRESULT_FROM_WIN32(lastError);
    }
    if (attributes & FILE_ATTRIBUTE_DIRECTORY)
    {
        WcaLog(LOGMSG_STANDARD, "%ls '%ls' is a directory.", label, path);
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

BOOL MsiIdentifierNameIsValid(LPCWSTR value)
{
    if (value == NULL)
    {
        return FALSE;
    }

    size_t len = 0;
    if (FAILED(StringCchLengthW(value, 65, &len)) || len == 0 || len > 64)
    {
        return FALSE;
    }

    for (size_t i = 0; i < len; i++)
    {
        WCHAR ch = value[i];
        BOOL isAlpha = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
        BOOL isDigit = ch >= L'0' && ch <= L'9';
        if (i == 0 && !isAlpha)
        {
            return FALSE;
        }
        if (i == len - 1 && !(isAlpha || isDigit))
        {
            return FALSE;
        }
        if (!(isAlpha || isDigit || ch == L'-'))
        {
            return FALSE;
        }
    }

    return TRUE;
}

HRESULT ValidateDeferredProductExecutablePath(
    LPCWSTR exePath,
    BOOL requireExistingFile,
    LPWSTR normalizedExe,
    size_t normalizedExeCch,
    LPWSTR exeNameNoExt,
    size_t exeNameNoExtCch)
{
    HRESULT hr = NormalizeMsiFilePath(exePath, normalizedExe, normalizedExeCch, L"MSI executable");
    if (FAILED(hr))
    {
        return hr;
    }

    WCHAR installFolder[MAX_PATH] = { 0 };
    hr = StringCchCopyW(installFolder, MAX_PATH, normalizedExe);
    if (FAILED(hr))
    {
        return hr;
    }
    if (!PathRemoveFileSpecW(installFolder))
    {
        WcaLog(LOGMSG_STANDARD, "MSI executable has no parent: '%ls'.", normalizedExe);
        return E_INVALIDARG;
    }

    WCHAR normalizedInstallFolder[MAX_PATH] = { 0 };
    hr = ValidateDeferredInstallFolder(installFolder, normalizedInstallFolder, MAX_PATH);
    if (FAILED(hr))
    {
        return hr;
    }

    LPCWSTR exeName = PathFindFileNameW(normalizedExe);
    if (exeName == NULL || exeName[0] == L'\0')
    {
        WcaLog(LOGMSG_STANDARD, "MSI executable has no filename: '%ls'.", normalizedExe);
        return E_INVALIDARG;
    }

    hr = StringCchCopyW(exeNameNoExt, exeNameNoExtCch, exeName);
    if (FAILED(hr))
    {
        return hr;
    }

    size_t exeNameLen = 0;
    hr = StringCchLengthW(exeNameNoExt, exeNameNoExtCch, &exeNameLen);
    if (FAILED(hr))
    {
        return hr;
    }
    if (exeNameLen <= 4 || CompareStringOrdinal(exeNameNoExt + exeNameLen - 4, -1, L".exe", -1, TRUE) != CSTR_EQUAL)
    {
        WcaLog(LOGMSG_STANDARD, "MSI executable does not have a .exe filename: '%ls'.", normalizedExe);
        return E_INVALIDARG;
    }

    exeNameNoExt[exeNameLen - 4] = L'\0';
    if (!MsiIdentifierNameIsValid(exeNameNoExt))
    {
        WcaLog(LOGMSG_STANDARD, "MSI executable name is not a valid system identifier: '%ls'.", exeNameNoExt);
        return E_INVALIDARG;
    }

    if (requireExistingFile)
    {
        hr = RequireExistingMsiFileNoReparse(normalizedExe, L"MSI executable");
        if (FAILED(hr))
        {
            return hr;
        }
    }

    return S_OK;
}

HRESULT ValidateServiceExecutablePath(LPCWSTR serviceName, LPCWSTR exePath, LPWSTR normalizedExe, size_t normalizedExeCch)
{
    WCHAR exeNameNoExt[500] = { 0 };
    HRESULT hr = ValidateDeferredProductExecutablePath(exePath, TRUE, normalizedExe, normalizedExeCch, exeNameNoExt, 500);
    if (FAILED(hr))
    {
        return hr;
    }

    if (!PathsEqualNoCase(exeNameNoExt, serviceName))
    {
        WcaLog(LOGMSG_STANDARD, "MSI service executable name '%ls' does not match service '%ls'.", exeNameNoExt, serviceName);
        return E_INVALIDARG;
    }

    return S_OK;
}

HRESULT ValidateServiceBinaryCommandAndExecutable(
    LPCWSTR serviceName,
    LPCWSTR svcBinary,
    LPWSTR normalizedCommand,
    size_t normalizedCommandCch,
    LPWSTR normalizedExecutable,
    size_t normalizedExecutableCch)
{
    if (svcBinary == NULL || svcBinary[0] == L'\0')
    {
        WcaLog(LOGMSG_STANDARD, "MSI service binary command is empty.");
        return E_INVALIDARG;
    }
    if (svcBinary[0] != L'"')
    {
        WcaLog(LOGMSG_STANDARD, "MSI service binary command is not quoted: '%ls'.", svcBinary);
        return E_INVALIDARG;
    }

    LPCWSTR closingQuote = wcschr(svcBinary + 1, L'"');
    if (closingQuote == NULL)
    {
        WcaLog(LOGMSG_STANDARD, "MSI service binary command is missing the closing quote: '%ls'.", svcBinary);
        return E_INVALIDARG;
    }
    if (wcscmp(closingQuote + 1, L" --service") != 0)
    {
        WcaLog(LOGMSG_STANDARD, "MSI service binary command has unexpected arguments: '%ls'.", svcBinary);
        return E_INVALIDARG;
    }
    if (wcschr(closingQuote + 1, L';') != NULL)
    {
        WcaLog(LOGMSG_STANDARD, "MSI service binary command contains an extra delimiter: '%ls'.", svcBinary);
        return E_INVALIDARG;
    }

    size_t exePathLen = closingQuote - (svcBinary + 1);
    if (exePathLen == 0 || exePathLen >= MAX_PATH)
    {
        WcaLog(LOGMSG_STANDARD, "MSI service executable path length is invalid.");
        return E_INVALIDARG;
    }

    WCHAR exePath[MAX_PATH] = { 0 };
    HRESULT hr = StringCchCopyNW(exePath, MAX_PATH, svcBinary + 1, exePathLen);
    if (FAILED(hr))
    {
        return hr;
    }

    hr = ValidateServiceExecutablePath(serviceName, exePath, normalizedExecutable, normalizedExecutableCch);
    if (FAILED(hr))
    {
        return hr;
    }

    return StringCchPrintfW(normalizedCommand, normalizedCommandCch, L"\"%ls\" --service", normalizedExecutable);
}

HRESULT ValidateServiceBinaryCommand(LPCWSTR serviceName, LPCWSTR svcBinary, LPWSTR normalizedCommand, size_t normalizedCommandCch)
{
    WCHAR normalizedExecutable[MAX_PATH] = { 0 };
    return ValidateServiceBinaryCommandAndExecutable(
        serviceName,
        svcBinary,
        normalizedCommand,
        normalizedCommandCch,
        normalizedExecutable,
        MAX_PATH);
}

HRESULT ValidateInstalledServiceBinaryCommand(SC_HANDLE hService, LPCWSTR serviceName, LPCWSTR expectedCommand)
{
    DWORD bytesNeeded = 0;
    if (QueryServiceConfigW(hService, NULL, 0, &bytesNeeded))
    {
        WcaLog(LOGMSG_STANDARD, "Unexpected empty service config for '%ls'.", serviceName);
        return E_FAIL;
    }

    DWORD lastError = GetLastError();
    if (lastError != ERROR_INSUFFICIENT_BUFFER || bytesNeeded == 0)
    {
        WcaLog(LOGMSG_STANDARD, "Failed to size service config for '%ls'. Error: %lu", serviceName, lastError);
        return HRESULT_FROM_WIN32(lastError);
    }

    LPQUERY_SERVICE_CONFIGW serviceConfig = static_cast<LPQUERY_SERVICE_CONFIGW>(LocalAlloc(LPTR, bytesNeeded));
    if (serviceConfig == NULL)
    {
        return E_OUTOFMEMORY;
    }

    HRESULT hr = S_OK;
    if (!QueryServiceConfigW(hService, serviceConfig, bytesNeeded, &bytesNeeded))
    {
        lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to query service config for '%ls'. Error: %lu", serviceName, lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto LExit;
    }

    {
        WCHAR normalizedInstalledCommand[1024] = { 0 };
        hr = ValidateServiceBinaryCommand(serviceName, serviceConfig->lpBinaryPathName, normalizedInstalledCommand, 1024);
        if (FAILED(hr))
        {
            WcaLog(LOGMSG_STANDARD, "Installed service command is not trusted for '%ls'.", serviceName);
            goto LExit;
        }

        if (!PathsEqualNoCase(normalizedInstalledCommand, expectedCommand))
        {
            WcaLog(
                LOGMSG_STANDARD,
                "Installed service command for '%ls' does not match package command. Installed='%ls' Package='%ls'.",
                serviceName,
                normalizedInstalledCommand,
                expectedCommand);
            hr = E_INVALIDARG;
            goto LExit;
        }
    }

LExit:
    LocalFree(serviceConfig);
    return hr;
}

HRESULT StopDeleteTrustedService(LPCWSTR serviceName, LPCWSTR expectedCommand, BOOL* serviceWasPresent)
{
    if (serviceWasPresent != NULL)
    {
        *serviceWasPresent = FALSE;
    }

    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL)
    {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to open Service Control Manager. Error: 0x%02X", lastError);
        return HRESULT_FROM_WIN32(lastError);
    }

    HRESULT hr = S_OK;
    SC_HANDLE hService = OpenServiceW(
        hSCManager,
        serviceName,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
    if (hService == NULL)
    {
        DWORD lastError = GetLastError();
        if (lastError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            WcaLog(LOGMSG_STANDARD, "Service \"%ls\" does not exist.", serviceName);
            goto LExit;
        }
        WcaLog(LOGMSG_STANDARD, "Failed to open service before deletion: \"%ls\", error: 0x%02X.", serviceName, lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto LExit;
    }

    if (serviceWasPresent != NULL)
    {
        *serviceWasPresent = TRUE;
    }

    hr = ValidateInstalledServiceBinaryCommand(hService, serviceName, expectedCommand);
    if (FAILED(hr))
    {
        goto LExit;
    }

    {
        SERVICE_STATUS_PROCESS svcStatus = { 0 };
        DWORD bytesNeeded = 0;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&svcStatus), sizeof(svcStatus), &bytesNeeded))
        {
            DWORD lastError = GetLastError();
            WcaLog(LOGMSG_STANDARD, "Failed to query service before deletion: \"%ls\", error: 0x%02X.", serviceName, lastError);
            hr = HRESULT_FROM_WIN32(lastError);
            goto LExit;
        }

        if (svcStatus.dwCurrentState == SERVICE_RUNNING)
        {
            SERVICE_STATUS serviceStatus = { 0 };
            if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus))
            {
                DWORD lastError = GetLastError();
                if (lastError != ERROR_SERVICE_NOT_ACTIVE)
                {
                    WcaLog(LOGMSG_STANDARD, "Failed to stop service: \"%ls\", error: 0x%02X.", serviceName, lastError);
                    hr = HRESULT_FROM_WIN32(lastError);
                    goto LExit;
                }
            }

            for (int i = 0; i < 10; i++)
            {
                if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&svcStatus), sizeof(svcStatus), &bytesNeeded))
                {
                    DWORD lastError = GetLastError();
                    WcaLog(LOGMSG_STANDARD, "Failed to query service while stopping: \"%ls\", error: 0x%02X.", serviceName, lastError);
                    hr = HRESULT_FROM_WIN32(lastError);
                    goto LExit;
                }
                if (svcStatus.dwCurrentState != SERVICE_RUNNING)
                {
                    break;
                }
                Sleep(100);
            }
        }

        if (svcStatus.dwCurrentState == SERVICE_RUNNING)
        {
            WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is not stopped after 1000 ms.", serviceName);
            hr = E_FAIL;
            goto LExit;
        }
        WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is stopped.", serviceName);

        if (!DeleteService(hService))
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                WcaLog(LOGMSG_STANDARD, "Service \"%ls\" was already deleted.", serviceName);
                goto LExit;
            }
            WcaLog(LOGMSG_STANDARD, "Failed to delete service: \"%ls\", error: 0x%02X.", serviceName, lastError);
            hr = HRESULT_FROM_WIN32(lastError);
            goto LExit;
        }
        WcaLog(LOGMSG_STANDARD, "Service \"%ls\" deletion is completed without errors.", serviceName);

        CloseServiceHandle(hService);
        hService = NULL;

        SC_HANDLE hVerifyService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
        if (hVerifyService != NULL)
        {
            SERVICE_STATUS_PROCESS currentStatus = { 0 };
            DWORD verifyBytesNeeded = 0;
            if (QueryServiceStatusEx(
                    hVerifyService,
                    SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(&currentStatus),
                    sizeof(currentStatus),
                    &verifyBytesNeeded))
            {
                WcaLog(LOGMSG_STANDARD, "Failed to delete service: \"%ls\", current status: %d.", serviceName, currentStatus.dwCurrentState);
            }
            CloseServiceHandle(hVerifyService);
            hr = E_FAIL;
            goto LExit;
        }

        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is deleted.", serviceName);
            }
            else
            {
                WcaLog(LOGMSG_STANDARD, "Failed to verify service deletion: \"%ls\", error: 0x%02X.", serviceName, lastError);
                hr = HRESULT_FROM_WIN32(lastError);
            }
        }
    }

LExit:
    if (hService != NULL)
    {
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);
    return hr;
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
// Upgrade/uninstall sequence:
//   1. InstallInitialize
//   2. RemoveExistingProducts
//      ├─ TerminateProcesses
//      ├─ TryStopDeleteService
//      ├─ RemoveRuntimeGeneratedFiles - <-- Here
//      └─ RemoveFiles
//   3. InstallValidate
//   4. InstallFiles
//   5. InstallExecute
//   6. InstallFinalize
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

// https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
// **NtQueryInformationProcess** may be altered or unavailable in future versions of Windows.
// Applications should use the alternate functions listed in this topic.
// But I do not find the alternate functions.
// https://github.com/heim-rs/heim/issues/105#issuecomment-683647573
typedef NTSTATUS(NTAPI *pfnNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
bool TerminateProcessIfNotContainsParam(pfnNtQueryInformationProcess NtQueryInformationProcess, HANDLE process, LPCWSTR excludeParam)
{
    bool processClosed = false;
    PROCESS_BASIC_INFORMATION processInfo;
    NTSTATUS status = NtQueryInformationProcess(process, ProcessBasicInformation, &processInfo, sizeof(processInfo), NULL);
    if (status == 0 && processInfo.PebBaseAddress != NULL)
    {
        PEB peb;
        SIZE_T dwBytesRead;
        if (ReadProcessMemory(process, processInfo.PebBaseAddress, &peb, sizeof(peb), &dwBytesRead))
        {
            RTL_USER_PROCESS_PARAMETERS pebUpp;
            if (ReadProcessMemory(process,
                                  peb.ProcessParameters,
                                  &pebUpp,
                                  sizeof(RTL_USER_PROCESS_PARAMETERS),
                                  &dwBytesRead))
            {
                if (pebUpp.CommandLine.Length > 0)
                {
                    // Allocate extra space for null terminator
                    WCHAR *commandLine = (WCHAR *)malloc(pebUpp.CommandLine.Length + sizeof(WCHAR));
                    if (commandLine != NULL)
                    {
                        // Initialize all bytes to zero for safety
                        memset(commandLine, 0, pebUpp.CommandLine.Length + sizeof(WCHAR));
                        if (ReadProcessMemory(process, pebUpp.CommandLine.Buffer,
                                              commandLine, pebUpp.CommandLine.Length, &dwBytesRead))
                        {
                            if (wcsstr(commandLine, excludeParam) == NULL)
                            {
                                WcaLog(LOGMSG_STANDARD, "Terminate process : %ls", commandLine);
                                TerminateProcess(process, 0);
                                processClosed = true;
                            }
                        }
                        free(commandLine);
                    }
                }
            }
        }
    }
    return processClosed;
}

// Terminate processes that do not have parameter [excludeParam]
// Note. This function relies on "NtQueryInformationProcess",
//       which may not be found.
//       Then all processes of [processName] will be terminated.
bool TerminateProcessesByNameW(LPCWSTR processName, LPCWSTR excludeParam)
{
    HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
    if (hntdll == NULL)
    {
        WcaLog(LOGMSG_STANDARD, "Failed to load ntdll.");
    }

    pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
    if (hntdll != NULL)
    {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(
            hntdll, "NtQueryInformationProcess");
    }
    if (NtQueryInformationProcess == NULL)
    {
        WcaLog(LOGMSG_STANDARD, "Failed to get address of NtQueryInformationProcess.");
    }

    bool processClosed = false;
    // Create a snapshot of the current system processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(snapshot, &processEntry))
        {
            do
            {
                if (lstrcmpW(processName, processEntry.szExeFile) == 0)
                {
                    HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processEntry.th32ProcessID);
                    if (process != NULL)
                    {
                        if (NtQueryInformationProcess == NULL)
                        {
                            WcaLog(LOGMSG_STANDARD, "Terminate process : %ls, while NtQueryInformationProcess is NULL", processName);
                            TerminateProcess(process, 0);
                            processClosed = true;
                        }
                        else
                        {
                            processClosed = TerminateProcessIfNotContainsParam(
                                NtQueryInformationProcess,
                                process,
                                excludeParam);
                        }
                        CloseHandle(process);
                    }
                }
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processClosed;
}

bool TerminateProcessesByImagePathW(LPCWSTR expectedImagePath, LPCWSTR excludeParam)
{
    WCHAR expectedNormalized[MAX_PATH] = { 0 };
    HRESULT hr = NormalizeMsiFilePath(expectedImagePath, expectedNormalized, MAX_PATH, L"process cleanup image path");
    if (FAILED(hr))
    {
        return false;
    }

    LPCWSTR expectedFileName = PathFindFileNameW(expectedNormalized);
    if (expectedFileName == NULL || expectedFileName[0] == L'\0')
    {
        return false;
    }

    HMODULE hntdll = GetModuleHandleW(L"ntdll.dll");
    pfnNtQueryInformationProcess NtQueryInformationProcess = NULL;
    if (hntdll != NULL)
    {
        NtQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(
            hntdll, "NtQueryInformationProcess");
    }

    bool processClosed = false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(snapshot, &processEntry))
    {
        do
        {
            if (!PathsEqualNoCase(expectedFileName, processEntry.szExeFile))
            {
                continue;
            }

            HANDLE process = OpenProcess(
                PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                processEntry.th32ProcessID);
            if (process == NULL)
            {
                continue;
            }

            WCHAR imagePath[MAX_PATH] = { 0 };
            DWORD imagePathCch = MAX_PATH;
            if (QueryFullProcessImageNameW(process, 0, imagePath, &imagePathCch))
            {
                WCHAR normalizedImagePath[MAX_PATH] = { 0 };
                if (SUCCEEDED(NormalizeMsiFilePath(imagePath, normalizedImagePath, MAX_PATH, L"running process image path")) &&
                    PathsEqualNoCase(normalizedImagePath, expectedNormalized))
                {
                    if (NtQueryInformationProcess == NULL)
                    {
                        WcaLog(LOGMSG_STANDARD, "Terminate process by trusted image path : %ls", normalizedImagePath);
                        TerminateProcess(process, 0);
                        processClosed = true;
                    }
                    else if (TerminateProcessIfNotContainsParam(NtQueryInformationProcess, process, excludeParam))
                    {
                        processClosed = true;
                    }
                }
            }

            CloseHandle(process);
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return processClosed;
}

UINT __stdcall TerminateProcesses(
    __in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    wchar_t szProcess[256] = {0};
    DWORD cchProcess = sizeof(szProcess) / sizeof(szProcess[0]);

    hr = WcaInitialize(hInstall, "TerminateProcesses");
    ExitOnFailure(hr, "Failed to initialize");

    MsiGetPropertyW(hInstall, L"TerminateProcesses", szProcess, &cchProcess);

    WcaLog(LOGMSG_STANDARD, "Try terminate processes : %ls", szProcess);
    TerminateProcessesByNameW(szProcess, L"--install");

LExit:
    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}

UINT __stdcall AddFirewallRules(
    __in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    LPWSTR exeFile = NULL;
    WCHAR exeNameNoExt[500] = { 0, };
    WCHAR normalizedExeFile[MAX_PATH] = { 0 };
    LPWSTR pwz = NULL;
    LPWSTR pwzData = NULL;

    hr = WcaInitialize(hInstall, "AddFirewallRules");
    ExitOnFailure(hr, "Failed to initialize");

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &exeFile);
    ExitOnFailure(hr, "failed to read database key from custom action data: %ls", pwz);
    WcaLog(LOGMSG_STANDARD, "Try add firewall exceptions for file : %ls", exeFile);

    if (exeFile[0] != L'0' && exeFile[0] != L'1') {
        WcaLog(LOGMSG_STANDARD, "Malformed firewall CustomActionData: %ls", exeFile);
        hr = E_INVALIDARG;
        goto LExit;
    }
    if (exeFile[1] == L'\0') {
        WcaLog(LOGMSG_STANDARD, "Firewall CustomActionData contains an empty executable path");
        hr = E_INVALIDARG;
        goto LExit;
    }

    hr = ValidateDeferredProductExecutablePath(exeFile + 1, exeFile[0] == L'1', normalizedExeFile, MAX_PATH, exeNameNoExt, 500);
    ExitOnFailure(hr, "Firewall executable path is not trusted");

    hr = AddFirewallRule(exeFile[0] == L'1', exeNameNoExt, normalizedExeFile);
    ExitOnFailure(hr, "Failed to update firewall rules for: %ls", normalizedExeFile);

LExit:
    if (pwzData) {
        ReleaseStr(pwzData);
    }

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}

UINT __stdcall CreateStartService(__in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    LPWSTR svcParams = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzData = NULL;
    LPWSTR svcName = NULL;
    LPWSTR svcBinary = NULL;
    wchar_t szSvcDisplayName[500] = { 0 };
    wchar_t szSvcBinary[1024] = { 0 };
    DWORD cchSvcDisplayName = sizeof(szSvcDisplayName) / sizeof(szSvcDisplayName[0]);
    DWORD cchSvcBinary = sizeof(szSvcBinary) / sizeof(szSvcBinary[0]);

    hr = WcaInitialize(hInstall, "CreateStartService");
    ExitOnFailure(hr, "Failed to initialize");

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &svcParams);
    ExitOnFailure(hr, "failed to read database key from custom action data: %ls", pwz);

    WcaLog(LOGMSG_STANDARD, "Try create start service : %ls", svcParams);

    svcName = svcParams;
    svcBinary = wcschr(svcParams, L';');
    if (svcBinary == NULL) {
        WcaLog(LOGMSG_STANDARD, "Failed to find binary : %ls", svcParams);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service CustomActionData");
    }
    svcBinary[0] = L'\0';
    svcBinary += 1;
    if (wcschr(svcBinary, L';') != NULL) {
        WcaLog(LOGMSG_STANDARD, "Service CustomActionData contains an extra delimiter : %ls", svcBinary);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service CustomActionData");
    }
    if (!MsiIdentifierNameIsValid(svcName)) {
        WcaLog(LOGMSG_STANDARD, "Service name is not a valid system identifier : %ls", svcName);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service name");
    }
    hr = ValidateServiceBinaryCommand(svcName, svcBinary, szSvcBinary, cchSvcBinary);
    ExitOnFailure(hr, "Malformed service binary command");

    hr = StringCchPrintfW(szSvcDisplayName, cchSvcDisplayName, L"%ls Service", svcName);
    ExitOnFailure(hr, "Failed to compose a resource identifier string");
    if (!MyCreateServiceW(svcName, szSvcDisplayName, szSvcBinary)) {
        WcaLog(LOGMSG_STANDARD, "Failed to create service: \"%ls\"", svcName);
        hr = E_FAIL;
        ExitOnFailure(hr, "Failed to create service");
    }
    WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is created.", svcName);

    if (!MyStartServiceW(svcName)) {
        WcaLog(LOGMSG_STANDARD, "Failed to start service: \"%ls\"", svcName);
        hr = E_FAIL;
        ExitOnFailure(hr, "Failed to start service");
    }
    WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is started.", svcName);

    if (IsServiceRunningW(svcName)) {
        WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is running.", svcName);
    }
    else {
        WcaLog(LOGMSG_STANDARD, "Service \"%ls\" is not running.", svcName);
        hr = E_FAIL;
        ExitOnFailure(hr, "Service is not running after start");
    }

LExit:
    if (pwzData) {
        ReleaseStr(pwzData);
    }

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}

UINT __stdcall TryStopDeleteService(__in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    BOOL serviceWasPresent = FALSE;
    LPWSTR svcParams = NULL;
    LPWSTR svcName = NULL;
    LPWSTR svcBinary = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzData = NULL;
    wchar_t szSvcBinary[1024] = { 0 };
    wchar_t szSvcExecutable[MAX_PATH] = { 0 };
    DWORD cchSvcBinary = sizeof(szSvcBinary) / sizeof(szSvcBinary[0]);

    hr = WcaInitialize(hInstall, "TryStopDeleteService");
    ExitOnFailure(hr, "Failed to initialize");

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &svcParams);
    ExitOnFailure(hr, "failed to read database key from custom action data: %ls", pwz);
    WcaLog(LOGMSG_STANDARD, "Try stop and delete service : %ls", svcParams);

    svcName = svcParams;
    svcBinary = wcschr(svcParams, L';');
    if (svcBinary == NULL) {
        WcaLog(LOGMSG_STANDARD, "Failed to find service binary command : %ls", svcParams);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service deletion CustomActionData");
    }
    svcBinary[0] = L'\0';
    svcBinary += 1;
    if (wcschr(svcBinary, L';') != NULL) {
        WcaLog(LOGMSG_STANDARD, "Service deletion CustomActionData contains an extra delimiter : %ls", svcBinary);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service deletion CustomActionData");
    }
    if (!MsiIdentifierNameIsValid(svcName)) {
        WcaLog(LOGMSG_STANDARD, "Service name is not a valid system identifier : %ls", svcName);
        hr = E_INVALIDARG;
        ExitOnFailure(hr, "Malformed service name");
    }

    hr = ValidateServiceBinaryCommandAndExecutable(svcName, svcBinary, szSvcBinary, cchSvcBinary, szSvcExecutable, MAX_PATH);
    ExitOnFailure(hr, "Malformed service deletion binary command");

    hr = StopDeleteTrustedService(svcName, szSvcBinary, &serviceWasPresent);
    ExitOnFailure(hr, "Failed to stop and delete trusted service");

    if (serviceWasPresent) {
        TerminateProcessesByImagePathW(szSvcExecutable, L"--not-in-use");
    }

LExit:
    if (pwzData) {
        ReleaseStr(pwzData);
    }

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}

UINT __stdcall RemoveAmyuniIdd(
    __in MSIHANDLE hInstall)
{
    HRESULT hr = S_OK;
    DWORD er = ERROR_SUCCESS;

    LPWSTR installFolder = NULL;
    LPWSTR pwz = NULL;
    LPWSTR pwzData = NULL;

    WCHAR normalizedInstallFolder[MAX_PATH] = L"";
    WCHAR workDir[1024] = L"";
    WCHAR commandLine[2048] = L"";
    STARTUPINFOW startupInfo = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    DWORD waitResult = 0;
    DWORD exitCode = 0;

    SYSTEM_INFO nativeSystemInfo;
    LPCWSTR exe = L"deviceinstaller64.exe";
    WCHAR exePath[1024] = L"";

    BOOL rebootRequired = FALSE;
    DriverUninstallStatus uninstallStatus = DriverUninstallNotPresent;
    HRESULT setupApiHr = S_OK;

    hr = WcaInitialize(hInstall, "RemoveAmyuniIdd");
    ExitOnFailure(hr, "Failed to initialize");

    setupApiHr = UninstallDriver(L"usbmmidd", uninstallStatus, rebootRequired);
    if (FAILED(setupApiHr)) {
        WcaLog(LOGMSG_STANDARD, "SetupAPI Amyuni IDD removal failed: 0x%08lx", setupApiHr);
    }
    else if (uninstallStatus == DriverUninstallNotPresent) {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD device is not present");
        goto LExit;
    }
    else {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD device removed through SetupAPI");
        goto LExit;
    }

    // Only for x86 app on x64
    GetNativeSystemInfo(&nativeSystemInfo);
    if (nativeSystemInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64) {
        hr = setupApiHr;
        goto LExit;
    }

    hr = WcaGetProperty(L"CustomActionData", &pwzData);
    ExitOnFailure(hr, "failed to get CustomActionData");

    pwz = pwzData;
    hr = WcaReadStringFromCaData(&pwz, &installFolder);
    ExitOnFailure(hr, "failed to read database key from custom action data: %ls", pwz);

    hr = ValidateDeferredInstallFolder(installFolder, normalizedInstallFolder, MAX_PATH);
    ExitOnFailure(hr, "Amyuni install folder is not trusted");

    hr = StringCchPrintfW(workDir, 1024, L"%ls\\usbmmidd_v2", normalizedInstallFolder);
    ExitOnFailure(hr, "Failed to compose a resource identifier string");

    hr = RequireExistingMsiDirectoryNoReparse(workDir, L"Amyuni IDD directory");
    if (FAILED(hr)) {
        hr = FAILED(setupApiHr) ? setupApiHr : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto LExit;
    }

    hr = StringCchPrintfW(exePath, 1024, L"%ls\\%ls", workDir, exe);
    ExitOnFailure(hr, "Failed to compose a resource identifier string");

    hr = RequireExistingMsiFileNoReparse(exePath, L"Amyuni IDD helper");
    if (FAILED(hr)) {
        hr = FAILED(setupApiHr) ? setupApiHr : HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND);
        goto LExit;
    }

    WcaLog(LOGMSG_STANDARD, "Remove amyuni idd %ls", exePath);
    hr = StringCchPrintfW(commandLine, 2048, L"\"%ls\" remove usbmmidd", exePath);
    ExitOnFailure(hr, "Failed to compose amyuni idd command line");

    startupInfo.cb = sizeof(startupInfo);
    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_HIDE;

    if (!CreateProcessW(exePath, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, workDir, &startupInfo, &pi)) {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to launch amyuni idd removal helper: %lu", lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto LExit;
    }

    waitResult = WaitForSingleObject(pi.hProcess, 120000);
    if (waitResult != WAIT_OBJECT_0) {
        DWORD lastError = waitResult == WAIT_FAILED ? GetLastError() : waitResult;
        WcaLog(LOGMSG_STANDARD, "Amyuni idd removal helper did not complete: wait result %lu, error %lu", waitResult, lastError);
        TerminateProcess(pi.hProcess, ERROR_TIMEOUT);
        hr = waitResult == WAIT_FAILED ? HRESULT_FROM_WIN32(lastError) : HRESULT_FROM_WIN32(ERROR_TIMEOUT);
        goto LExit;
    }

    if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
        DWORD lastError = GetLastError();
        WcaLog(LOGMSG_STANDARD, "Failed to read amyuni idd removal helper exit code: %lu", lastError);
        hr = HRESULT_FROM_WIN32(lastError);
        goto LExit;
    }

    if (exitCode == ERROR_SUCCESS_REBOOT_REQUIRED) {
        rebootRequired = TRUE;
    }
    else if (exitCode != 0) {
        WcaLog(LOGMSG_STANDARD, "Amyuni idd removal helper failed with exit code %lu", exitCode);
        hr = E_FAIL;
        goto LExit;
    }

    WcaLog(LOGMSG_STANDARD, "Amyuni idd is removed");
    hr = S_OK;

LExit:
    if (rebootRequired && SUCCEEDED(hr)) {
        WcaLog(LOGMSG_STANDARD, "Amyuni IDD removal requires reboot");
        HRESULT rebootHr = WcaDeferredActionRequiresReboot();
        if (FAILED(rebootHr)) {
            WcaLog(LOGMSG_STANDARD, "Failed to signal Amyuni IDD reboot requirement: 0x%08lx", rebootHr);
            hr = rebootHr;
        }
    }
    if (pi.hThread) {
        CloseHandle(pi.hThread);
    }
    if (pi.hProcess) {
        CloseHandle(pi.hProcess);
    }
    if (pwzData) {
        ReleaseStr(pwzData);
    }

    er = SUCCEEDED(hr) ? ERROR_SUCCESS : ERROR_INSTALL_FAILURE;
    return WcaFinalize(er);
}
