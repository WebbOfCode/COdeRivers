@echo off
REM ----------------------------------------------------------
REM Safe-URL-Check — Windows startup helper
REM Responsibilities:
REM  - Locate Python and set up a .venv
REM  - Install requirements
REM  - Load simple .env (KEY=VALUE) pairs
REM  - Launch Flask app with helpful console tips
REM ----------------------------------------------------------
setlocal enabledelayedexpansion

REM Resolve repo base directory and enter it
set "BASEDIR=%~dp0"
pushd "%BASEDIR%"

echo === Safe-URL-Check Startup ===

REM Detect a Python launcher/command on PATH
set "PY_CMD="
where py >nul 2>&1 && set "PY_CMD=py"
if not defined PY_CMD (
	where python >nul 2>&1 && set "PY_CMD=python"
)
if not defined PY_CMD (
	echo Python is not available on PATH. Install Python 3.9+ and rerun this script.
	goto :cleanup
)

REM Create a virtual environment on first run
if not exist ".venv\Scripts\python.exe" (
	echo Creating virtual environment...
	if "%PY_CMD%"=="py" (
		%PY_CMD% -3 -m venv .venv || goto :venv_error
	) else (
		%PY_CMD% -m venv .venv || goto :venv_error
	)
)

set "PYTHON_EXE=%BASEDIR%\.venv\Scripts\python.exe"
if not exist "%PYTHON_EXE%" goto :venv_error

echo Upgrading pip and installing dependencies...
"%PYTHON_EXE%" -m pip install --upgrade pip >nul
"%PYTHON_EXE%" -m pip install -r requirements.txt || goto :pip_error

REM Install dependencies and provide hints
echo Using interpreter: %PYTHON_EXE%
if not defined SAFE_BROWSING_API_KEY (
	echo TIP: Set SAFE_BROWSING_API_KEY before scanning to enable Google Safe Browsing checks.
)
REM Load .env if present (simple KEY=VALUE without quotes)
if exist ".env" (
	for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
		if not "%%A"=="" if not "%%A"=="#" set "%%A=%%B"
	)
)

set "HOST_DISPLAY=%HOST%"
if not defined HOST_DISPLAY set "HOST_DISPLAY=127.0.0.1"
set "PORT_DISPLAY=%PORT%"
if not defined PORT_DISPLAY set "PORT_DISPLAY=5000"

REM Start Flask app using configured host/port
echo Starting Safe-URL-Check on http://%HOST_DISPLAY%:%PORT_DISPLAY%
"%PYTHON_EXE%" app.py
if not "%NO_PAUSE%"=="1" (
	echo.
	echo Press any key to close this window...
	pause >nul
)
goto :cleanup

:venv_error
echo Failed to create or locate the virtual environment under .venv.
goto :cleanup

:pip_error
echo Dependency installation failed. Review the error output above.

:cleanup
popd
endlocal
