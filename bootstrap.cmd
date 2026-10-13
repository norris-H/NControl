@echo off
setlocal

rem Resolve the script directory without the trailing backslash. A trailing
rem backslash before pip's closing quote is interpreted incorrectly on Windows.
for %%I in ("%~dp0.") do set "NCONTROL_ROOT=%%~fI"
set "NCONTROL_PYTHON=%NCONTROL_ROOT%\.venv\Scripts\python.exe"

if not exist "%NCONTROL_PYTHON%" (
  where py >nul 2>&1
  if not errorlevel 1 (
    py -3 -m venv --clear "%NCONTROL_ROOT%\.venv"
  ) else (
    python -m venv --clear "%NCONTROL_ROOT%\.venv"
  )
  if errorlevel 1 exit /b 1
)

"%NCONTROL_PYTHON%" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
"%NCONTROL_PYTHON%" -m pip install -e "%NCONTROL_ROOT%"
if errorlevel 1 exit /b 1

echo NControl is ready. Run: ncontrol.cmd
