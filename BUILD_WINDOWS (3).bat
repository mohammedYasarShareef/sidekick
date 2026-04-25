@echo off
setlocal
echo ============================================
echo   Sidekick EDR v5.0 - Windows Build Script
echo ============================================
echo.

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

if not exist "sidekick.py" (
    echo ERROR: sidekick.py not found in %SCRIPT_DIR%
    echo Make sure sidekick.py and BUILD_WINDOWS.bat are in the SAME folder.
    pause & exit /b 1
)

echo [1/3] Installing dependencies...
pip install customtkinter psutil cryptography pyinstaller kyber-py
if errorlevel 1 ( echo ERROR: pip install failed. & pause & exit /b 1 )

echo.
echo [2/3] Building standalone .exe ...
pyinstaller --noconsole --onefile --name "Sidekick" ^
  --hidden-import customtkinter ^
  --hidden-import psutil ^
  --hidden-import cryptography ^
  --hidden-import cryptography.fernet ^
  --hidden-import cryptography.hazmat.primitives.ciphers.aead ^
  --hidden-import kyber_py ^
  --hidden-import kyber_py.kyber ^
  --collect-all customtkinter ^
  --collect-all kyber_py ^
  "%SCRIPT_DIR%sidekick.py"

if errorlevel 1 ( echo ERROR: Build failed. & pause & exit /b 1 )

echo.
echo [3/3] Done!
echo Your executable: dist\Sidekick.exe
echo.
echo Send ONLY Sidekick.exe to users - no dependencies needed on their machine.
echo.
pause
