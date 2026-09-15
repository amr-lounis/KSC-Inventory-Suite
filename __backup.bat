@echo off
setlocal enabledelayedexpansion
set ARCHIVE_DIR=..\archive
mkdir "%ARCHIVE_DIR%" 2>nul

:: Find last version
set MAX=0
for %%F in ("%ARCHIVE_DIR%\v*.zip") do (
    set "NAME=%%~nF"
    set "NUM=!NAME:~1!"
    if !NUM! gtr !MAX! set MAX=!NUM!
)
set /a NEXT=MAX+1
set VERSION=v%NEXT%

:: Commit
set /p COMMIT_VALUE=Enter commit message [%VERSION%]: 
if "%COMMIT_VALUE%"=="" set COMMIT_VALUE=%VERSION%

git add .
git commit -m "%COMMIT_VALUE%"
git archive --format zip --output "%ARCHIVE_DIR%\%VERSION%.zip" HEAD

echo.
echo Created: %ARCHIVE_DIR%\%VERSION%.zip
echo.
echo --- Content of %ARCHIVE_DIR% ---
dir /b /o-n "%ARCHIVE_DIR%"

pause