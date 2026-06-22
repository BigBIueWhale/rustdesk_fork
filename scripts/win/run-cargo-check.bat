@echo off
REM scripts\win\run-cargo-check.bat -- decoupled cfg(windows) cargo-check runner.
REM
REM cmd-based (not PowerShell) on purpose: it runs cleanly under a Windows Scheduled
REM Task in session 0, where the SSH-driven PowerShell path drops the channel the
REM moment the heavy parallel compile starts (cargo --version survives; cargo check
REM does not). vcvars64.bat is itself a .bat, so cmd hosts it natively -- no
REM "import the env into PowerShell" dance. Mirror of winenv.ps1's environment.
REM
REM Usage:  run-cargo-check.bat <features>   (e.g. flutter | inline)
REM Writes: C:\tools\cc.log (full output) and C:\tools\cc.rc (RC=<n>).
setlocal
if "%~1"=="" (set "FEATURES=flutter") else (set "FEATURES=%~1")
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set "VCPKG_ROOT=C:\vcpkg"
set "VCPKG_DEFAULT_TRIPLET=x64-windows-static"
set "LIBCLANG_PATH=C:\Program Files\LLVM\bin"
set "PATH=C:\Users\builder\.cargo\bin;C:\Program Files\Git\cmd;%PATH%"
cd /d C:\src
cargo check --locked --target x86_64-pc-windows-msvc --features %FEATURES% > C:\tools\cc.log 2>&1
REM Leading redirect: `echo RC=%errorlevel%>file` would parse a trailing digit + `>`
REM as a redirect handle (e.g. RC=0 -> empty file). Redirect first, echo second.
>"C:\tools\cc.rc" echo RC=%errorlevel%
endlocal
