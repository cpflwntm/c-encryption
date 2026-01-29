@echo off
SETLOCAL enabledelayedexpansion
set OLD_PATH=%PATH%

REM -------------------------------------------------------------------------------------------
REM -    Options
REM -------------------------------------------------------------------------------------------

set ARMCC_PATH=C:\Keil\ARM\ARMCC\bin

REM -------------------------------------------------------------------------------------------
REM -    Input Options
REM -------------------------------------------------------------------------------------------

set CLEAN_EN=0
set "BUILD_TARGET=all"

REM -------------------------------------------------------------------------------------------

:parse_args

if "%~1"=="" goto end_parse

if /I "%~1"=="clean" (
    set CLEAN_EN=1
    shift
    goto parse_args
) else if /I "%~1"=="rsa3072" (
    set BUILD_TARGET=rsa3072
    shift
    goto parse_args
) else if /I "%~1"=="aes256cbc" (
    set BUILD_TARGET=aes256cbc
    shift
    goto parse_args
) else (
    shift
    goto parse_args
)

:end_parse

REM -------------------------------------------------------------------------------------------

set PATH=%ARMCC_PATH%;%OLD_PATH%

REM -------------------------------------------------------------------------------------------
REM -          Library Build
REM -------------------------------------------------------------------------------------------
echo.
echo ----------------------------------------------
echo [ Crypto Library Build Start ]
echo  clean  : %CLEAN_EN%
echo  target : %BUILD_TARGET%
echo ----------------------------------------------
echo.

REM -------------------------------------------------------------------------------------------

if "%CLEAN_EN%"=="1" (
    make clean -f Makefile.mak
    if !ERRORLEVEL! NEQ 0 (
        echo Clean Error ! ERRORLEVEL=!ERRORLEVEL!
        goto BAT_EXEC_ERR
    )
)

make %BUILD_TARGET% -f Makefile.mak
if %ERRORLEVEL% NEQ 0 (
    echo Build Error ! ERRORLEVEL=%ERRORLEVEL%
    goto BAT_EXEC_ERR
)

echo ----------------------------------------------
echo Build Finished
echo ----------------------------------------------

exit /b 0

REM -------------------------------------------------------------------------------------------

:USAGE
echo -----------------------------------------------------------------------
echo "Usage: Build.bat [clean] [rsa3072|aes256cbc]"
echo -----------------------------------------------------------------------
echo "clean build (o)     : clean"
echo "build target (o)    : rsa3072 / aes256cbc (default: all)"
echo.
echo "ex ) ./Build.bat clean"
echo "ex ) ./Build.bat clean rsa3072"
echo "ex ) ./Build.bat aes256cbc"
exit /b 100

:BAT_EXEC_ERR
exit /b 101
