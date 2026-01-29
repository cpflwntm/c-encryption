@echo off
setlocal enabledelayedexpansion

REM -------------------------------------------------------------------------------------------

echo -----------------------------------------------------------------------
echo Crypto Library Build (RSA3072 / AES256CBC)
echo -----------------------------------------------------------------------
echo 0: All libraries (rsa3072.lib + aes256cbc.lib)
echo 1: rsa3072.lib only
echo 2: aes256cbc.lib only
echo -----------------------------------------------------------------------

:SEL_PROJECT
set /p PROJECT=select target ? :
set /A PROJECT=%PROJECT% 2>nul

if %PROJECT% GTR 2 (
    goto SEL_PROJECT
)

echo -----------------------------------------------------------------------

set /p CLEAN_BUILD=Perform a Clean Build ? (Y/n):
ver > nul

if /I "%CLEAN_BUILD%"=="n" (
    set CLEAN_BUILD=
) else (
    set CLEAN_BUILD=clean
)

echo -----------------------------------------------------------------------

if %PROJECT% EQU 0 (
    call ./Build.bat %CLEAN_BUILD%
) else if %PROJECT% EQU 1 (
    call ./Build.bat %CLEAN_BUILD% rsa3072
) else if %PROJECT% EQU 2 (
    call ./Build.bat %CLEAN_BUILD% aes256cbc
)

if !ERRORLEVEL! NEQ 0 (
    goto ERROR
)

goto END

REM -------------------------------------------------------------------------------------------

:ERROR
echo Build Error  ERRORLEVEL=%ERRORLEVEL%

:END

pause
