@echo off
setlocal EnableDelayedExpansion

:: ============================================================
:: Configuration - edit paths to match your environment
:: ============================================================
set "QT_DIR=D:\Qt\6.11.1\mingw_64"
set "QT_TOOLS=D:\Qt\Tools\mingw1310_64\bin"
set "OPENSSL_ROOT=D:\Qt\Tools\mingw1310_64\opt"
set "NINJA_DIR=D:\Qt\Tools\Ninja"
set "CMAKE_DIR=D:\Qt\Tools\CMake_64\bin"
set "BUILD_DIR=cmake-build-release"
:: ============================================================

set "PATH=%CMAKE_DIR%;%QT_DIR%\bin;%QT_TOOLS%;%NINJA_DIR%;%PATH%"

set "ARG=%~1"

if /i "%ARG%"=="clean" goto :CLEAN
if /i "%ARG%"=="rebuild" (
    call :CLEAN_DIR
    goto :CONFIGURE
)

if exist "%BUILD_DIR%\build.ninja" (
    echo [SKIP] Already configured - incremental build...
    goto :BUILD
)

:CONFIGURE
echo [1/3] CMake configure...
cmake -S . -B "%BUILD_DIR%" -G Ninja ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DQT_INSTALL_PREFIX="%QT_DIR%" ^
      -DOPENSSL_ROOT_DIR="%OPENSSL_ROOT%"
if errorlevel 1 ( echo [ERROR] Configure failed & pause & exit /b 1 )

:BUILD
echo [2/3] Build...
cmake --build "%BUILD_DIR%" --config Release -j%NUMBER_OF_PROCESSORS%
if errorlevel 1 ( echo [ERROR] Build failed & pause & exit /b 1 )

echo [3/3] Deploy...
if not exist dist mkdir dist
copy /y "%BUILD_DIR%\AdaptixClient.exe" dist\ >nul

pushd dist
"%QT_DIR%\bin\windeployqt.exe" AdaptixClient.exe
popd

for %%D in (
    libwinpthread-1.dll
    libgcc_s_seh-1.dll
    libstdc++-6.dll
    libfreetype-6.dll
    libharfbuzz-0.dll
    libmd4c.dll
    libpng16-16.dll
    zlib1.dll
    libb2-1.dll
    libdouble-conversion.dll
    libicuin78.dll
    libicuuc78.dll
    libpcre2-16-0.dll
    libbrotlidec.dll
    libzstd.dll
    libbz2-1.dll
    libglib-2.0-0.dll
    libgraphite2.dll
    libbrotlicommon.dll
    libicudt78.dll
    libpcre2-8-0.dll
    libintl-8.dll
    libiconv-2.dll
) do (
    if exist "%QT_TOOLS%\%%D" copy /y "%QT_TOOLS%\%%D" dist\ >nul
)

echo.
echo [OK] Done!  Output: dist\AdaptixClient.exe
goto :EOF

:CLEAN
call :CLEAN_DIR
echo [OK] Cleaned.
goto :EOF

:CLEAN_DIR
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist dist rmdir /s /q dist
exit /b 0
