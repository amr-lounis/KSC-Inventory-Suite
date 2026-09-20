@echo off
setlocal
title Build Kaspersky Inventory EXE

echo ====================================================
echo  Kaspersky Inventory - Build EXE
echo ====================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found in PATH
    pause
    exit /b 1
)

echo [1/4] Upgrading pip...
python -m pip install --upgrade pip

echo.
echo [2/4] Installing dependencies...
pip install -r requirements.txt
pip install pyinstaller

echo.
echo [3/4] Cleaning old build...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
if exist __pycache__ rmdir /s /q __pycache__
del /q *.spec 2>nul

echo.
echo [4/4] Building EXE (gui.py)...
:: --onefile : single exe
:: --windowed : no console (GUI only)
:: --name : output name
:: --add-data : include example settings
pyinstaller --noconfirm --onefile --windowed --name KasperskyInventory --add-data "settings.example.json;." --hidden-import openpyxl --hidden-import et_xmlfile --hidden-import vuln_check --hidden-import vuln_update gui.py

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed
    pause
    exit /b 1
)

echo.
echo ====================================================
echo  Build completed!
echo  EXE: dist\KasperskyInventory.exe
echo ====================================================
dir dist\*.exe
pause
