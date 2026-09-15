@echo off
setlocal enabledelayedexpansion

:: === Kaspersky Inventory - Backup & Archive Script (fixed) ===
:: Fixes: injection-safe commit message, respects .gitignore, warns about secrets, robust paths

set "ARCHIVE_DIR=..\archive"
mkdir "%ARCHIVE_DIR%" 2>nul
if not exist "%ARCHIVE_DIR%" (
    echo [ERROR] Cannot create archive dir: %ARCHIVE_DIR%
    pause
    exit /b 1
)

:: Check git repo
git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Not inside a git repository
    pause
    exit /b 1
)

:: Find last version
set MAX=0
for %%F in ("%ARCHIVE_DIR%\v*.zip") do (
    set "NAME=%%~nF"
    set "NUM=!NAME:~1!"
    :: ensure numeric
    echo !NUM! | findstr /r "^[0-9][0-9]*$" >nul
    if !errorlevel! == 0 (
        if !NUM! gtr !MAX! set MAX=!NUM!
    )
)
set /a NEXT=MAX+1
set "VERSION=v%NEXT%"

:: Show status before commit
echo.
echo --- git status ---
git status --short
echo.

:: Warn about potential secrets in staged/unstaged files
echo --- Checking for potential secrets (KSC_PASSWORD / hardcoded IP) ---
git diff --cached --no-color | findstr /i "KSC_PASSWORD Test@12345678" >nul 2>&1
if !errorlevel! == 0 (
    echo [WARNING] Staged changes contain potential secrets! Review before committing.
    echo.
)
git diff --no-color | findstr /i "KSC_PASSWORD.*Test@" >nul 2>&1
if !errorlevel! == 0 (
    echo [WARNING] Working tree contains hardcoded password pattern. Ensure .env is used.
    echo.
)

:: Commit message - injection safe via temp file
set /p COMMIT_VALUE=Enter commit message [%VERSION%]: 
if "!COMMIT_VALUE!"=="" set "COMMIT_VALUE=%VERSION%"

:: Write commit message to temp file to avoid shell injection via git commit -m
set "TMPMSG=%TEMP%\ksc_commit_%RANDOM%.txt"
> "!TMPMSG!" echo !COMMIT_VALUE!

:: Stage only tracked + not-ignored files (respects .gitignore, won't add .env / *.json ignored)
:: Use -A but git respects .gitignore by default; --no-all would also respect
git add -A
if errorlevel 1 (
    echo [ERROR] git add failed
    del /f /q "!TMPMSG!" 2>nul
    pause
    exit /b 1
)

:: Check if there is anything to commit
git diff --cached --quiet
if !errorlevel! == 0 (
    echo [INFO] No changes to commit
) else (
    git commit -F "!TMPMSG!"
    if errorlevel 1 (
        echo [ERROR] git commit failed
        del /f /q "!TMPMSG!" 2>nul
        pause
        exit /b 1
    )
)

del /f /q "!TMPMSG!" 2>nul

:: Create archive from HEAD (fails if no commits yet)
git rev-parse HEAD >nul 2>&1
if errorlevel 1 (
    echo [ERROR] No commits yet, cannot archive
    pause
    exit /b 1
)

set "ZIP_PATH=%ARCHIVE_DIR%\%VERSION%.zip"
git archive --format zip --output "%ZIP_PATH%" HEAD
if errorlevel 1 (
    echo [ERROR] git archive failed
    pause
    exit /b 1
)

echo.
echo Created: %ZIP_PATH%
echo.
echo --- Content of %ARCHIVE_DIR% ---
dir /b /o-n "%ARCHIVE_DIR%"

pause
