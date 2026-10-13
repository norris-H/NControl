@echo off
setlocal

for %%I in ("%~dp0.") do set "NCONTROL_ROOT=%%~fI"
if not exist "%NCONTROL_ROOT%\local\services" if not exist "%NCONTROL_ROOT%\services" mkdir "%NCONTROL_ROOT%\local\services"
set "NCONTROL_PYTHON=%NCONTROL_ROOT%\.venv\Scripts\python.exe"

if not exist "%NCONTROL_PYTHON%" (
  where py >nul 2>&1
  if not errorlevel 1 (
    set "NCONTROL_PYTHON=py"
  ) else (
    set "NCONTROL_PYTHON=python"
  )
)

"%NCONTROL_PYTHON%" -c "import psutil, textual, yaml" >nul 2>&1
if errorlevel 1 (
  echo NControl dependencies are missing. Run bootstrap.cmd first. 1>&2
  exit /b 2
)

if defined PYTHONPATH (
  set "PYTHONPATH=%NCONTROL_ROOT%\src;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%NCONTROL_ROOT%\src"
)

"%NCONTROL_PYTHON%" -m homelabctl --root "%NCONTROL_ROOT%" %*
exit /b %errorlevel%
