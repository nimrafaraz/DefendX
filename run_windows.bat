@echo off
REM DEFEND-X launcher for Windows.
REM   run_windows.bat        -> set up (first time only) and start the app
REM   run_windows.bat test   -> set up and run the automated tests
setlocal
cd /d "%~dp0"

set "PYCMD="
where py >nul 2>nul && set "PYCMD=py -3"
if not defined PYCMD (
    where python >nul 2>nul && set "PYCMD=python"
)
if not defined PYCMD (
    echo.
    echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during installation. Then run this file again.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating virtual environment in .venv ...
    %PYCMD% -m venv .venv
    if errorlevel 1 (
        echo Could not create the virtual environment.
        pause
        exit /b 1
    )
)

echo Installing / checking requirements (first time needs internet) ...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Package installation failed. Check your internet connection and try again.
    pause
    exit /b 1
)

if /i "%~1"=="test" (
    ".venv\Scripts\python.exe" -m pytest
    set "RESULT=%errorlevel%"
    pause
    exit /b %RESULT%
)

REM Stop Streamlit asking for an e-mail address on the very first run.
if not exist "%USERPROFILE%\.streamlit\credentials.toml" (
    if not exist "%USERPROFILE%\.streamlit" mkdir "%USERPROFILE%\.streamlit"
    (echo [general]& echo email = "") > "%USERPROFILE%\.streamlit\credentials.toml"
)

echo.
echo Starting DEFEND-X. Your browser should open; if not, go to http://localhost:8501
echo Press Ctrl+C in this window to stop the app.
".venv\Scripts\python.exe" -m streamlit run app.py
pause
