#include <windows.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <cstdio>
#include <cstdint>
#include <intrin.h>
#include <algorithm>
#include <string>
#include <memory>
#include <shlobj.h> // NOLINT(build/include_order)
#include <userenv.h>
#include <versionhelpers.h>
#include <vector>
#include <sddl.h>
#include <memory>
#include <utility>

extern "C" uint32_t get_session_user_info(PWSTR bufin, uint32_t nin, uint32_t id);

void flog(char const *fmt, ...)
{
    FILE *h = fopen("C:\\Windows\\temp\\test_rustdesk.log", "at");
    if (!h)
        return;
    va_list arg;
    va_start(arg, fmt);
    vfprintf(h, fmt, arg);
    va_end(arg);
    fclose(h);
}

static const DWORD kCreateProcessTokenAccess = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
static const DWORD kWtsUserTokenSource = 0xFFFFFFFF;

static bool token_session_matches(HANDLE token, DWORD dwSessionId)
{
    DWORD tokenSessionId = 0;
    DWORD returned = 0;
    return GetTokenInformation(token,
                               TokenSessionId,
                               &tokenSessionId,
                               sizeof(tokenSessionId),
                               &returned) &&
           tokenSessionId == dwSessionId;
}

static bool token_user_is_local_system(HANDLE token)
{
    BYTE localSystemSid[SECURITY_MAX_SID_SIZE];
    DWORD localSystemSidSize = sizeof(localSystemSid);
    if (!CreateWellKnownSid(WinLocalSystemSid, NULL, localSystemSid, &localSystemSidSize))
    {
        return false;
    }

    DWORD tokenInfoLength = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &tokenInfoLength);
    if (tokenInfoLength == 0)
    {
        return false;
    }
    std::vector<BYTE> tokenInfo(tokenInfoLength);
    if (!GetTokenInformation(token, TokenUser, tokenInfo.data(), tokenInfoLength, &tokenInfoLength))
    {
        return false;
    }
    PTOKEN_USER tokenUser = reinterpret_cast<PTOKEN_USER>(tokenInfo.data());
    return EqualSid(tokenUser->User.Sid, localSystemSid);
}

static bool system32_executable_path(LPCWSTR exeName, std::wstring &path)
{
    std::vector<wchar_t> systemDir(MAX_PATH);
    UINT len = GetSystemDirectoryW(systemDir.data(), static_cast<UINT>(systemDir.size()));
    if (len >= systemDir.size())
    {
        systemDir.resize(static_cast<size_t>(len) + 1);
        len = GetSystemDirectoryW(systemDir.data(), static_cast<UINT>(systemDir.size()));
    }
    if (len == 0 || len >= systemDir.size())
    {
        return false;
    }
    path.assign(systemDir.data(), len);
    path.append(L"\\");
    path.append(exeName);
    return true;
}

static bool process_image_matches(HANDLE hProcess, const std::wstring &expectedPath)
{
    std::vector<wchar_t> imagePath(32768);
    DWORD imagePathLen = static_cast<DWORD>(imagePath.size());
    if (!QueryFullProcessImageNameW(hProcess, 0, imagePath.data(), &imagePathLen))
    {
        return false;
    }
    std::wstring actualPath(imagePath.data(), imagePathLen);
    return _wcsicmp(actualPath.c_str(), expectedPath.c_str()) == 0;
}

static BOOL query_logged_on_user_token(DWORD dwSessionId, LPHANDLE lphUserToken, DWORD *pDwTokenPid)
{
    HANDLE hToken = NULL;
    if (pDwTokenPid)
        *pDwTokenPid = 0;
    if (!WTSQueryUserToken(dwSessionId, &hToken))
    {
        return FALSE;
    }
    if (!token_session_matches(hToken, dwSessionId))
    {
        CloseHandle(hToken);
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    *lphUserToken = hToken;
    if (pDwTokenPid)
        *pDwTokenPid = kWtsUserTokenSource;
    return TRUE;
}

static BOOL query_trusted_winlogon_token(DWORD dwSessionId, LPHANDLE lphUserToken, DWORD *pDwTokenPid)
{
    if (pDwTokenPid)
        *pDwTokenPid = 0;
    std::wstring expectedWinlogonPath;
    if (!system32_executable_path(L"winlogon.exe", expectedWinlogonPath))
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }

    PROCESSENTRY32W procEntry;
    procEntry.dwSize = sizeof procEntry;
    if (Process32FirstW(hSnap, &procEntry))
    {
        do
        {
            DWORD processSessionId = 0;
            if (_wcsicmp(procEntry.szExeFile, L"winlogon.exe") != 0 ||
                !ProcessIdToSessionId(procEntry.th32ProcessID, &processSessionId) ||
                processSessionId != dwSessionId)
            {
                continue;
            }

            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procEntry.th32ProcessID);
            if (hProcess == NULL)
            {
                continue;
            }
            if (!process_image_matches(hProcess, expectedWinlogonPath))
            {
                CloseHandle(hProcess);
                continue;
            }

            HANDLE hToken = NULL;
            if (!OpenProcessToken(hProcess, kCreateProcessTokenAccess, &hToken))
            {
                CloseHandle(hProcess);
                continue;
            }
            CloseHandle(hProcess);

            if (!token_session_matches(hToken, dwSessionId) || !token_user_is_local_system(hToken))
            {
                CloseHandle(hToken);
                continue;
            }

            *lphUserToken = hToken;
            if (pDwTokenPid)
                *pDwTokenPid = procEntry.th32ProcessID;
            CloseHandle(hSnap);
            return TRUE;
        } while (Process32NextW(hSnap, &procEntry));
    }
    CloseHandle(hSnap);
    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

static bool has_extra_environment(LPCWSTR extraEnvironment)
{
    return extraEnvironment && extraEnvironment[0] != L'\0';
}

static std::wstring environment_entry_key(const std::wstring &entry)
{
    size_t searchStart = !entry.empty() && entry[0] == L'=' ? 1 : 0;
    size_t separator = entry.find(L'=', searchStart);
    if (separator == std::wstring::npos)
        return entry;
    return entry.substr(0, separator);
}

static int compare_environment_text(const std::wstring &left, const std::wstring &right, BOOL ignoreCase)
{
    int result = CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, ignoreCase);
    if (result == CSTR_LESS_THAN)
        return -1;
    if (result == CSTR_GREATER_THAN)
        return 1;
    return 0;
}

static bool environment_keys_equal(const std::wstring &left, const std::wstring &right)
{
    return compare_environment_text(left, right, TRUE) == 0;
}

static bool environment_entry_less(const std::wstring &left, const std::wstring &right)
{
    std::wstring leftKey = environment_entry_key(left);
    std::wstring rightKey = environment_entry_key(right);
    int keyOrder = compare_environment_text(leftKey, rightKey, TRUE);
    if (keyOrder != 0)
        return keyOrder < 0;
    return compare_environment_text(left, right, FALSE) < 0;
}

static void append_environment_entries(std::vector<std::wstring> &entries, LPCWSTR environment)
{
    if (!environment)
        return;

    LPCWSTR cursor = environment;
    while (*cursor)
    {
        size_t len = wcslen(cursor);
        entries.emplace_back(cursor, len);
        cursor += len + 1;
    }
}

static std::vector<wchar_t> merge_environment_blocks(LPVOID baseEnvironment, LPCWSTR extraEnvironment)
{
    std::vector<std::wstring> baseEntries;
    std::vector<std::wstring> extraEntries;
    append_environment_entries(baseEntries, static_cast<LPCWSTR>(baseEnvironment));
    append_environment_entries(extraEntries, extraEnvironment);

    for (const auto &extra : extraEntries)
    {
        std::wstring extraKey = environment_entry_key(extra);
        baseEntries.erase(
            std::remove_if(baseEntries.begin(), baseEntries.end(), [&](const std::wstring &base) {
                return environment_keys_equal(environment_entry_key(base), extraKey);
            }),
            baseEntries.end());
    }

    std::vector<std::wstring> entries = std::move(baseEntries);
    for (const auto &extra : extraEntries)
    {
        std::wstring extraKey = environment_entry_key(extra);
        auto existing = std::find_if(entries.begin(), entries.end(), [&](const std::wstring &entry) {
            return environment_keys_equal(environment_entry_key(entry), extraKey);
        });
        if (existing != entries.end())
        {
            *existing = extra;
        }
        else
        {
            entries.push_back(extra);
        }
    }

    std::sort(entries.begin(), entries.end(), environment_entry_less);

    std::vector<wchar_t> merged;
    for (const auto &entry : entries)
    {
        merged.insert(merged.end(), entry.c_str(), entry.c_str() + entry.size() + 1);
    }
    merged.push_back(L'\0');
    if (merged.size() == 1)
        merged.push_back(L'\0');
    return merged;
}

// START the app as system
extern "C"
{
    BOOL GetSessionUserTokenWin(OUT LPHANDLE lphUserToken, DWORD dwSessionId, BOOL as_user, DWORD *pDwTokenPid)
    {
        if (lphUserToken == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        *lphUserToken = NULL;
        if (as_user)
        {
            return query_logged_on_user_token(dwSessionId, lphUserToken, pDwTokenPid);
        }
        return query_trusted_winlogon_token(dwSessionId, lphUserToken, pDwTokenPid);
    }

    bool is_windows_server()
    {
        return IsWindowsServer();
    }

    bool is_windows_10_or_greater()
    {
        return IsWindows10OrGreater();
    }

    HANDLE LaunchProcessWin(LPCWSTR application,
                            LPCWSTR cmd,
                            LPCWSTR currentDirectory,
                            DWORD dwSessionId,
                            BOOL as_user,
                            BOOL show,
                            LPCWSTR extraEnvironment,
                            HANDLE hJob,
                            DWORD *pProcessId,
                            DWORD *pDwTokenPid)
    {
        HANDLE hProcess = NULL;
        HANDLE hToken = NULL;
        if (application == NULL || application[0] == L'\0' || cmd == NULL || cmd[0] == L'\0' ||
            currentDirectory == NULL || currentDirectory[0] == L'\0' || pProcessId == NULL ||
            pDwTokenPid == NULL)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return hProcess;
        }
        *pProcessId = 0;
        *pDwTokenPid = 0;
        if (GetSessionUserTokenWin(&hToken, dwSessionId, as_user, pDwTokenPid))
        {
            STARTUPINFOEXW si;
            ZeroMemory(&si, sizeof si);
            si.StartupInfo.cb = hJob != NULL ? sizeof si : sizeof si.StartupInfo;
            si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            if (show)
            {
                si.StartupInfo.lpDesktop = (LPWSTR)L"winsta0\\default";
                si.StartupInfo.wShowWindow = SW_SHOW;
            }
            std::vector<wchar_t> commandLine(wcslen(cmd) + 1);
            if (wcscpy_s(commandLine.data(), commandLine.size(), cmd) != 0)
            {
                SetLastError(ERROR_INVALID_PARAMETER);
                CloseHandle(hToken);
                return hProcess;
            }
            PROCESS_INFORMATION pi;
            ZeroMemory(&pi, sizeof pi);
            LPVOID lpEnvironment = NULL;
            DWORD dwCreationFlags = DETACHED_PROCESS;
            std::vector<wchar_t> mergedEnvironment;
            if (as_user)
            {
                if (!CreateEnvironmentBlock(&lpEnvironment, hToken, FALSE))
                {
                    DWORD error = GetLastError();
                    CloseHandle(hToken);
                    SetLastError(error);
                    return hProcess;
                }
                if (lpEnvironment == NULL)
                {
                    CloseHandle(hToken);
                    SetLastError(ERROR_INVALID_DATA);
                    return hProcess;
                }
            }
            LPVOID processEnvironment = lpEnvironment;
            if (has_extra_environment(extraEnvironment))
            {
                mergedEnvironment = merge_environment_blocks(lpEnvironment, extraEnvironment);
                processEnvironment = mergedEnvironment.data();
            }
            if (processEnvironment)
            {
                dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
            }
            std::vector<unsigned char> attributeListStorage;
            HANDLE jobList[] = {hJob};
            if (hJob != NULL)
            {
                SIZE_T attributeListSize = 0;
                BOOL sizedAttributeList = InitializeProcThreadAttributeList(NULL, 1, 0, &attributeListSize);
                DWORD sizeError = GetLastError();
                if (sizedAttributeList || sizeError != ERROR_INSUFFICIENT_BUFFER || attributeListSize == 0)
                {
                    CloseHandle(hToken);
                    if (lpEnvironment)
                        DestroyEnvironmentBlock(lpEnvironment);
                    SetLastError(sizeError != ERROR_SUCCESS ? sizeError : ERROR_INVALID_DATA);
                    return hProcess;
                }
                attributeListStorage.resize(attributeListSize);
                si.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeListStorage.data());
                if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeListSize))
                {
                    DWORD error = GetLastError();
                    CloseHandle(hToken);
                    if (lpEnvironment)
                        DestroyEnvironmentBlock(lpEnvironment);
                    SetLastError(error);
                    return hProcess;
                }
                if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
                                               jobList, sizeof jobList, NULL, NULL))
                {
                    DWORD error = GetLastError();
                    DeleteProcThreadAttributeList(si.lpAttributeList);
                    CloseHandle(hToken);
                    if (lpEnvironment)
                        DestroyEnvironmentBlock(lpEnvironment);
                    SetLastError(error);
                    return hProcess;
                }
                dwCreationFlags |= EXTENDED_STARTUPINFO_PRESENT;
            }
            if (CreateProcessAsUserW(hToken, application, commandLine.data(), NULL, NULL, FALSE,
                                     dwCreationFlags, processEnvironment, currentDirectory,
                                     reinterpret_cast<LPSTARTUPINFOW>(&si), &pi))
            {
                hProcess = pi.hProcess;
                *pProcessId = pi.dwProcessId;
                CloseHandle(pi.hThread);
            }
            DWORD launchError = GetLastError();
            if (si.lpAttributeList)
                DeleteProcThreadAttributeList(si.lpAttributeList);
            CloseHandle(hToken);
            if (lpEnvironment)
                DestroyEnvironmentBlock(lpEnvironment);
            if (hProcess == NULL)
                SetLastError(launchError);
        }
        return hProcess;
    }

    // Switch the current thread to the specified desktop
    static bool
    switchToDesktop(HDESK desktop)
    {
        HDESK old_desktop = GetThreadDesktop(GetCurrentThreadId());
        if (!SetThreadDesktop(desktop))
        {
            return false;
        }
        if (!CloseDesktop(old_desktop))
        {
            //
        }
        return true;
    }

    // https://github.com/TigerVNC/tigervnc/blob/8c6c584377feba0e3b99eecb3ef33b28cee318cb/win/rfb_win32/Service.cxx

    // Determine whether the thread's current desktop is the input one
    BOOL
    inputDesktopSelected()
    {
        HDESK current = GetThreadDesktop(GetCurrentThreadId());
        HDESK input = OpenInputDesktop(0, FALSE,
                                       DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
                                           DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
                                           DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
                                           DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
        if (!input)
        {
            return FALSE;
        }

        DWORD size;
        char currentname[256];
        char inputname[256];

        if (!GetUserObjectInformation(current, UOI_NAME, currentname, sizeof(currentname), &size))
        {
            CloseDesktop(input);
            return FALSE;
        }
        if (!GetUserObjectInformation(input, UOI_NAME, inputname, sizeof(inputname), &size))
        {
            CloseDesktop(input);
            return FALSE;
        }
        CloseDesktop(input);
        // flog("%s %s\n", currentname, inputname);
        return strcmp(currentname, inputname) == 0 ? TRUE : FALSE;
    }

    // Switch the current thread into the input desktop
    bool
    selectInputDesktop()
    {
        // - Open the input desktop
        HDESK desktop = OpenInputDesktop(0, FALSE,
                                         DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
                                             DESKTOP_ENUMERATE | DESKTOP_HOOKCONTROL |
                                             DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS |
                                             DESKTOP_SWITCHDESKTOP | GENERIC_WRITE);
        if (!desktop)
        {
            return false;
        }

        // - Switch into it
        if (!switchToDesktop(desktop))
        {
            CloseDesktop(desktop);
            return false;
        }

        // ***
        DWORD size = 256;
        char currentname[256];
        if (GetUserObjectInformation(desktop, UOI_NAME, currentname, 256, &size))
        {
            //
        }

        return true;
    }

    int handleMask(uint8_t *rwbuffer, const uint8_t *mask, int width, int height, int bmWidthBytes, int bmHeight)
    {
        auto andMask = mask;
        auto andMaskSize = bmWidthBytes * bmHeight;
        auto offset = height * bmWidthBytes;
        auto xorMask = mask + offset;
        auto xorMaskSize = andMaskSize - offset;
        int doOutline = 0;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                int byte = y * bmWidthBytes + x / 8;
                int bit = 7 - x % 8;

                if (byte < andMaskSize && !(andMask[byte] & (1 << bit)))
                {
                    // Valid pixel, so make it opaque
                    rwbuffer[3] = 0xff;

                    // Black or white?
                    if (xorMask[byte] & (1 << bit))
                        rwbuffer[0] = rwbuffer[1] = rwbuffer[2] = 0xff;
                    else
                        rwbuffer[0] = rwbuffer[1] = rwbuffer[2] = 0;
                }
                else if (byte < xorMaskSize && xorMask[byte] & (1 << bit))
                {
                    // Replace any XORed pixels with black, because RFB doesn't support
                    // XORing of cursors.  XORing is used for the I-beam cursor, which is most
                    // often used over a white background, but also sometimes over a black
                    // background.  We set the XOR'd pixels to black, then draw a white outline
                    // around the whole cursor.

                    rwbuffer[0] = rwbuffer[1] = rwbuffer[2] = 0;
                    rwbuffer[3] = 0xff;

                    doOutline = 1;
                }
                else
                {
                    // Transparent pixel
                    rwbuffer[0] = rwbuffer[1] = rwbuffer[2] = rwbuffer[3] = 0;
                }

                rwbuffer += 4;
            }
        }
        return doOutline;
    }

    void drawOutline(uint8_t *out0, const uint8_t *in0, int width, int height, int out0_size)
    {
        auto in = in0;
        auto out0_end = out0 + out0_size;
        auto offset = width * 4 + 4;
        auto out = out0 + offset;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                // Visible pixel?
                if (in[3] > 0)
                {
                    auto n = 4 * 3;
                    auto p = out - (width + 2) * 4 - 4;
                    // Outline above...
                    if (p >= out0 && p + n <= out0_end)
                        memset(p, 0xff, n);
                    // ...besides...
                    p = out - 4;
                    if (p + n <= out0_end)
                        memset(p, 0xff, n);
                    // ...and above
                    p = out + (width + 2) * 4 - 4;
                    if (p + n <= out0_end)
                        memset(p, 0xff, n);
                }
                in += 4;
                out += 4;
            }
            // outline is slightly larger
            out += 2 * 4;
        }

        // Pass 2, overwrite with actual cursor
        in = in0;
        out = out0 + offset;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                if (in[3] > 0 && out + 4 <= out0_end)
                    memcpy(out, in, 4);
                in += 4;
                out += 4;
            }
            out += 2 * 4;
        }
    }

    int ffi(unsigned v)
    {
        static const int MultiplyDeBruijnBitPosition[32] =
            {
                0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
                31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9};
        return MultiplyDeBruijnBitPosition[((uint32_t)((v & -v) * 0x077CB531U)) >> 27];
    }

    int get_di_bits(uint8_t *out, HDC dc, HBITMAP hbmColor, int width, int height)
    {
        BITMAPV5HEADER bi;
        memset(&bi, 0, sizeof(BITMAPV5HEADER));

        bi.bV5Size = sizeof(BITMAPV5HEADER);
        bi.bV5Width = width;
        bi.bV5Height = -height; // Negative for top-down
        bi.bV5Planes = 1;
        bi.bV5BitCount = 32;
        bi.bV5Compression = BI_BITFIELDS;
        bi.bV5RedMask = 0x000000FF;
        bi.bV5GreenMask = 0x0000FF00;
        bi.bV5BlueMask = 0x00FF0000;
        bi.bV5AlphaMask = 0xFF000000;

        if (!GetDIBits(dc, hbmColor, 0, height,
                       out, (LPBITMAPINFO)&bi, DIB_RGB_COLORS))
            return 1;

        // We may not get the RGBA order we want, so shuffle things around
        int ridx, gidx, bidx, aidx;

        ridx = ffi(bi.bV5RedMask) / 8;
        gidx = ffi(bi.bV5GreenMask) / 8;
        bidx = ffi(bi.bV5BlueMask) / 8;
        // Usually not set properly
        aidx = 6 - ridx - gidx - bidx;

        if ((bi.bV5RedMask != ((unsigned)0xff << ridx * 8)) ||
            (bi.bV5GreenMask != ((unsigned)0xff << gidx * 8)) ||
            (bi.bV5BlueMask != ((unsigned)0xff << bidx * 8)))
            return 1;

        auto rwbuffer = out;
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                uint8_t r, g, b, a;

                r = rwbuffer[ridx];
                g = rwbuffer[gidx];
                b = rwbuffer[bidx];
                a = rwbuffer[aidx];

                rwbuffer[0] = r;
                rwbuffer[1] = g;
                rwbuffer[2] = b;
                rwbuffer[3] = a;

                rwbuffer += 4;
            }
        }
        return 0;
    }

    void blank_screen(BOOL set)
    {
        if (set)
        {
            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)2);
        }
        else
        {
            SendMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, (LPARAM)-1);
        }
    }

    void AddRecentDocument(PCWSTR path)
    {
        SHAddToRecentDocs(SHARD_PATHW, path);
    }

    DWORD get_current_session(BOOL include_rdp)
    {
        auto rdp_or_console = WTSGetActiveConsoleSessionId();
        if (!include_rdp)
            return rdp_or_console;
        PWTS_SESSION_INFOA pInfos;
        DWORD count;
        auto rdp = "rdp";
        auto nrdp = strlen(rdp);
        // https://github.com/rustdesk/rustdesk/discussions/937#discussioncomment-12373814 citrix session
        auto ica = "ica";
        auto nica = strlen(ica);
        if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pInfos, &count))
        {
            for (DWORD i = 0; i < count; i++)
            {
                auto info = pInfos[i];
                if (info.State == WTSActive)
                {
                    if (info.pWinStationName == NULL)
                        continue;
                    if (!stricmp(info.pWinStationName, "console"))
                    {
                        auto id = info.SessionId;
                        WTSFreeMemory(pInfos);
                        return id;
                    }
                    if (!strnicmp(info.pWinStationName, rdp, nrdp) || !strnicmp(info.pWinStationName, ica, nica))
                    {
                        rdp_or_console = info.SessionId;
                    }
                }
            }
            WTSFreeMemory(pInfos);
        }
        return rdp_or_console;
    }

    BOOL is_session_locked(DWORD session_id)
    {
        if (session_id == 0xFFFFFFFF) {
            return FALSE;
        }
        PWTSINFOEXW pInfo = NULL;
        DWORD bytes = 0;
        BOOL locked = FALSE;
        if (WTSQuerySessionInformationW(
                WTS_CURRENT_SERVER_HANDLE,
                session_id,
                WTSSessionInfoEx,
                (LPWSTR *)&pInfo,
                &bytes)) {
            if (pInfo && pInfo->Level == 1) {
                locked = (pInfo->Data.WTSInfoExLevel1.SessionFlags == WTS_SESSIONSTATE_LOCK);
            }
            if (pInfo) {
                WTSFreeMemory(pInfo);
            }
        }
        return locked;
    }

    uint32_t get_active_user(PWSTR bufin, uint32_t nin, BOOL rdp)
    {
        uint32_t nout = 0;
        auto id = get_current_session(rdp);
        PWSTR buf = NULL;
        DWORD n = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSUserName, &buf, &n))
        {
            if (buf)
            {
                nout = min(nin, n);
                memcpy(bufin, buf, nout);
                WTSFreeMemory(buf);
            }
        }
        return nout;
    }

    uint32_t get_session_user_info(PWSTR bufin, uint32_t nin, uint32_t id)
    {
        uint32_t nout = 0;
        PWSTR buf = NULL;
        DWORD n = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, id, WTSUserName, &buf, &n))
        {
            if (buf)
            {
                nout = min(nin, n);
                memcpy(bufin, buf, nout);
                WTSFreeMemory(buf);
            }
        }
        return nout;
    }

    void get_available_session_ids(PWSTR buf, uint32_t bufSize, BOOL include_rdp) {
        std::vector<std::wstring> sessionIds;
        PWTS_SESSION_INFOA pInfos = NULL;
        DWORD count;

        if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfos, &count)) {
            for (DWORD i = 0; i < count; i++) {
                auto info = pInfos[i];
                auto rdp = "rdp";
                auto nrdp = strlen(rdp);
                auto ica = "ica";
                auto nica = strlen(ica);
                if (info.State == WTSActive) {
                    if (info.pWinStationName == NULL)
                        continue;
                    if (info.SessionId == 65536 || info.SessionId == 655)
                        continue;

                    if (!stricmp(info.pWinStationName, "console")){
                        sessionIds.push_back(std::wstring(L"Console:") + std::to_wstring(info.SessionId));
                    }
                    else if (include_rdp && !strnicmp(info.pWinStationName, rdp, nrdp)) {
                        sessionIds.push_back(std::wstring(L"RDP:") + std::to_wstring(info.SessionId));
                    }
                    else if (include_rdp && !strnicmp(info.pWinStationName, ica, nica)) {
                        sessionIds.push_back(std::wstring(L"ICA:") + std::to_wstring(info.SessionId));
                    }
                }
            }
            WTSFreeMemory(pInfos);
        }

        std::wstring tmpStr;
        for (size_t i = 0; i < sessionIds.size(); i++) {
            if (i > 0) {
                tmpStr += L",";
            }
            tmpStr += sessionIds[i];
        }

        if (buf && !tmpStr.empty() && tmpStr.size() < bufSize) {
            wcsncpy_s(buf, bufSize, tmpStr.c_str(), tmpStr.size());
        }
    }
} // end of extern "C"

extern "C"
{
    // https://stackoverflow.com/questions/4023586/correct-way-to-find-out-if-a-service-is-running-as-the-system-user
    BOOL is_local_system()
    {
        HANDLE hToken;
        UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
        PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
        ULONG cbTokenUser;
        SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
        PSID pSystemSid;
        BOOL bSystem;

        // open process token
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_QUERY,
                              &hToken))
            return FALSE;

        // retrieve user SID
        if (!GetTokenInformation(hToken, TokenUser, pTokenUser,
                                 sizeof(bTokenUser), &cbTokenUser))
        {
            CloseHandle(hToken);
            return FALSE;
        }

        CloseHandle(hToken);

        // allocate LocalSystem well-known SID
        if (!AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID,
                                      0, 0, 0, 0, 0, 0, 0, &pSystemSid))
            return FALSE;

        // compare the user SID from the token with the LocalSystem SID
        bSystem = EqualSid(pTokenUser->User.Sid, pSystemSid);

        FreeSid(pSystemSid);

        return bSystem;
    }

    void alloc_console_and_redirect()
    {
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
    }

    bool is_service_running_w(LPCWSTR serviceName)
    {
        SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
        if (hSCManager == NULL) {
            return false;
        }

        SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_QUERY_STATUS);
        if (hService == NULL) {
            CloseServiceHandle(hSCManager);
            return false;
        }

        SERVICE_STATUS_PROCESS serviceStatus;
        DWORD bytesNeeded;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&serviceStatus), sizeof(serviceStatus), &bytesNeeded)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }

        bool isRunning = (serviceStatus.dwCurrentState == SERVICE_RUNNING);

        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);

        return isRunning;
    }
} // end of extern "C"
