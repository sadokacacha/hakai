@echo off
setlocal EnableDelayedExpansion

title Hakai v3 — Sovereign Apex

echo.
echo  ██╗  ██╗ █████╗ ██╗  ██╗ █████╗ ██╗
echo  ██║  ██║██╔══██╗██║ ██╔╝██╔══██╗██║
echo  ███████║███████║█████╔╝ ███████║██║
echo  ██╔══██║██╔══██║██╔═██╗ ██╔══██║██║
echo  ██║  ██║██║  ██║██║  ██╗██║  ██║██║
echo  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
echo.
echo  [*] Hakai v3 — Sovereign Apex Launcher
echo  ----------------------------------------

:: ── Locate Python ────────────────────────────────────────────────────────────
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Python not found. Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [+] Using: %PYVER%

:: ── Set paths ─────────────────────────────────────────────────────────────────
set SCRIPT_DIR=%~dp0
set VENV_DIR=%SCRIPT_DIR%venv

:: ── Create venv if missing ───────────────────────────────────────────────────
if not exist "%VENV_DIR%\Scripts\activate.bat" (
    echo  [*] Creating virtual environment in venv\...
    python -m venv "%VENV_DIR%"
    if %errorlevel% neq 0 (
        echo  [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [+] Virtual environment created.
) else (
    echo  [+] Virtual environment already exists — skipping creation.
)

:: ── Activate venv ────────────────────────────────────────────────────────────
echo  [*] Activating virtual environment...
call "%VENV_DIR%\Scripts\activate.bat"

:: ── Upgrade pip ──────────────────────────────────────────────────────────────
echo  [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: ── Install requirements ──────────────────────────────────────────────────────
if exist "%SCRIPT_DIR%requirements.txt" (
    echo  [*] Installing dependencies from requirements.txt...
    pip install -r "%SCRIPT_DIR%requirements.txt"
    if %errorlevel% neq 0 (
        echo  [!] Failed to install some dependencies.
        pause
        exit /b 1
    )
    echo  [+] All dependencies installed.
) else (
    echo  [!] requirements.txt not found — skipping pip install.
)

:: ── Launch Hakai ─────────────────────────────────────────────────────────────
echo.
echo  [*] Launching Hakai v3...
echo  [!] NOTE: Full network features require Linux + root privileges.
echo      On Windows, network scanning and ARP features may be limited.
echo.

cd /d "%SCRIPT_DIR%"
python main.py

:: ── Done ─────────────────────────────────────────────────────────────────────
echo.
echo  [*] Hakai exited.
pause
endlocal
