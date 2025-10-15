REM Disable command echoing to keep console output clean
@echo off
REM Comment explaining this script starts the Flask application
REM Start the Safe-URL-Check Flask app using the repository venv if present
REM Check if virtual environment activation script exists
if exist ".venv\Scripts\activate.bat" (
REM Activate the virtual environment if it exists
call .venv\Scripts\activate.bat
)
REM Display startup message with local URL
echo Starting Safe-URL-Check on http://127.0.0.1:5000
REM Run Python interpreter from venv with app.py as argument
REM %~dp0 expands to the directory path of this batch file
"%~dp0\.venv\Scripts\python.exe" "%~dp0app.py"
