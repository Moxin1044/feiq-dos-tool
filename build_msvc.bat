@echo off
rem ===========================================================================
rem  FeiQ DoS Tool - MSVC build script (x86 / no CRT / Windows XP compatible)
rem ---------------------------------------------------------------------------
rem  Key points:
rem    * Zero CRT dependency: /NODEFAULTLIB + custom entry WinMainCRTStartup
rem      => no vcruntime/ucrt imports, runs on Windows XP SP3
rem    * /GS-  disable stack cookie (avoids __security_cookie from CRT)
rem    * /SUBSYSTEM:WINDOWS,5.01  declare Windows XP as minimum OS
rem    * /utf-8  source is UTF-8; wide (W) APIs used for all UI text
rem ===========================================================================
setlocal
cd /d "%~dp0"

set "VCVARS="
rem --- level-by-level search (dir /s does not accept wildcards in the path) ---
for %%R in ("C:\Program Files\Microsoft Visual Studio" "C:\Program Files (x86)\Microsoft Visual Studio") do (
  if exist %%R (
    for /d %%A in ("%%~R\*") do (
      for /d %%B in ("%%~A\*") do (
        if exist "%%~B\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%%~B\VC\Auxiliary\Build\vcvars32.bat"
      )
      if exist "%%~A\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%%~A\VC\Auxiliary\Build\vcvars32.bat"
    )
  )
)
rem --- fallback: vswhere ---
if not defined VCVARS (
  set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
  if exist "!VSWHERE!" (
    for /f "usebackq delims=" %%I in (`"!VSWHERE!" -latest -property installationPath`) do (
      if exist "%%I\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%%I\VC\Auxiliary\Build\vcvars32.bat"
    )
  )
)
if not defined VCVARS (
  echo [x] vcvars32.bat not found. Run this inside a VS developer prompt.
  exit /b 1
)
echo [*] using: %VCVARS%
call "%VCVARS%" >nul
if errorlevel 1 (
  echo [x] failed to init VS environment
  exit /b 1
)

if not exist build mkdir build
if not exist bin   mkdir bin

echo [*] compiling ...
cl /nologo /c /O2 /GS- /W3 /Zl /utf-8 ^
   /D_WIN32_WINNT=0x0501 /DWINVER=0x0501 ^
   /Fobuild\feiq_dos.obj src\feiq_dos.c
if errorlevel 1 goto fail

echo [*] linking ...
link /nologo /SUBSYSTEM:WINDOWS,5.01 /ENTRY:WinMainCRTStartup /NODEFAULTLIB ^
     /OPT:REF /OPT:ICF ^
     /OUT:bin\feiq_dos.exe build\feiq_dos.obj ^
     kernel32.lib user32.lib gdi32.lib ws2_32.lib
if errorlevel 1 goto fail

echo.
echo [OK] built: bin\feiq_dos.exe
echo      verify imports with: dumpbin /dependents bin\feiq_dos.exe
exit /b 0

:fail
echo.
echo [x] build failed
exit /b 1
