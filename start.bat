REM Disable command echoing to keep console output clean
@echo off
REM Capture the directory where this script resides
set "BASEDIR=%~dp0"
REM Ensure we are running commands from the project root
pushd "%BASEDIR%"
REM Initialize variable that will point to the Python executable
set "PYTHON_EXE="
REM Check if the project virtual environment exists
if exist "%BASEDIR%\.venv\Scripts\activate.bat" (
REM Activate the virtual environment so dependencies are available
call "%BASEDIR%\.venv\Scripts\activate.bat"
REM Use the Python interpreter bundled inside the virtual environment
set "PYTHON_EXE=%BASEDIR%\.venv\Scripts\python.exe"
)
REM Fallback to system Python when inside-venv interpreter is not available
if not defined PYTHON_EXE (
REM Default to using python from the system PATH
set "PYTHON_EXE=python"
)
REM Inform the user which interpreter will launch the app
echo Using interpreter: %PYTHON_EXE%
REM Display startup message with local URL
echo Starting Safe-URL-Check on http://127.0.0.1:5000
REM Execute app.py with the chosen interpreter
%PYTHON_EXE% "%BASEDIR%app.py"
REM Return to the original directory after script execution
popd
