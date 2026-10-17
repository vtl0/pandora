@echo off
setlocal enabledelayedexpansion

echo Preparing EDK2 for Visual Studio compilation. Bug reports are welcome
echo:

echo [^>] Updating dependencies...
where git >nul 2>nul
if !errorlevel! neq 0 (
    echo [X] Git was not found in PATH. Install git or update your PATH.
    exit /b 1
)

if not exist "%target_dir%\" (
    git -C "%target_dir%" pull --recurse-submodules
) else (
    git clone --depth 1 --recursive https://github.com/tianocore/edk2.git edk2
)

set "EDK2_DIR=edk2"
if not exist "%EDK2_DIR%\edksetup.bat" (
    echo [X] Path %EDK2_DIR% is missing or incomplete. Did clone/update fail?
    exit /b 1
)

echo [^>] All submodules up to date.
echo [^>] Locating Visual Studio...
set "VS_PATH="
set "VS_VERSION="
for /f "tokens=1,* delims=:" %%a in ('^""%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -requires Microsoft.Component.MSBuild -format text^"') do (
    set "KEY=%%a"
    set "VAL=%%b"
    if "!VAL:~0,1!" == " " set "VAL=!VAL:~1!"
    
    if "!KEY!" == "installationPath" set "VS_PATH=!VAL!"
    if "!KEY!" == "installationVersion" set "VS_VERSION=!VAL!"
)

if not defined VS_PATH (
    echo [X] Could not find Visual Studio installation. Is it installed?
    exit /b 1
)

if not defined VS_VERSION (
    echo [X] VS_VERSION was not set. This is abnormal, report.
    exit /b 1
)

echo [^>] Loading Visual Studio environment variables...
set "VSLANG=1033"
if exist "%VS_PATH%\VC\Auxiliary\Build\vcvars32.bat" (
    call "%VS_PATH%\VC\Auxiliary\Build\vcvars32.bat" >nul
) else (
    if defined TOOL_CHAIN_VER_MISMATCH (
        echo [X] vcvars32.bat was not found. The path might have changed in this new Visual Studio version.
        echo     Current Visual Studio version is "%VS_VERSION%", path is "%VS_PATH%". Supported versions: VS2019,
        echo     VS2022, and VS2026. If the current version is not listed, feel free to contribute with a pull request.
    )
    echo [X] vcvars32.bat was not found in "%VS_PATH%\VC\Auxiliary\Build\" ^(broken installation?^)
    exit /b 1
)

echo [^>] Looking for clang binaries...
set "FOUND_CLANG_DIR="
if defined USE_SYSTEM_CLANG (
    if defined CLANG_BIN (
        set "TMP_PATH=%CLANG_BIN%"
        if "!TMP_PATH:~-1!" == "\" set "TMP_PATH=!TMP_PATH:~0,-1!"
        
        if exist "!TMP_PATH!\clang.exe" (
            set "FOUND_CLANG_DIR=!TMP_PATH!"
            echo [i] USE_SYSTEM_CLANG is set. Using %%CLANG_BIN%%
        )
    )
    if not defined FOUND_CLANG_DIR (
        echo [^^!] USE_SYSTEM_CLANG is set but %%CLANG_BIN%% does not contain a clang binary.
        echo       It will be searched in PATH. Note that this project requires clang and EDK2
        echo       must be compiled using the same LLVM version as Pandora. The build might fail.
        
        where clang >nul 2>nul
        if !errorlevel! equ 0 (
            for /f "tokens=*" %%i in ('where clang') do set "FOUND_CLANG_DIR=%%~dpi"
        )
    )
) else (
    if defined CLANG_BIN (
        echo [^^!] %%CLANG_BIN%% is set, but ignored. EDK2 has to be compiled using the same LLVM version
        echo       as Pandora. Visual Studio' clang will be used instead. To forcibly use %%CLANG_BIN%%,
        echo       set %%USE_SYSTEM_CLANG%%
    )
    if exist "%VS_PATH%\VC\Tools\Llvm\x64\bin\clang.exe" (
        set "FOUND_CLANG_DIR=%VS_PATH%\VC\Tools\Llvm\x64\bin"
    )
)

if not defined FOUND_CLANG_DIR (
    echo [X] Neither %%CLANG_BIN%% nor "%VS_PATH%\VC\Tools\Llvm\x64\bin" nor PATH contains a clang binary.
    echo     Install clang in Visual Studio installer. This is the best way forward, unless you're ready to
    echo     deal with matching LLVM/clang version for both EDK2 and Pandora
    exit /b 1
)

set "CLANG_BIN=%FOUND_CLANG_DIR%\"
set "CLANG_HOST_BIN=n"
echo [^>] Found Clang at: "%CLANG_BIN%"

echo [^>] Checking NASM
if defined NASM_PREFIX (
    set "NASM_PREFIX=!NASM_PREFIX:"=!"
    if not "!NASM_PREFIX:~-1!" == "\" set "NASM_PREFIX=!NASM_PREFIX!\"
) else (
    echo [^^!] NASM_PREFIX is undefined. Searching for nasm in PATH...
    where nasm >nul 2>nul

    if !errorlevel! equ 0 (
        for /f "tokens=*" %%i in ('where nasm') do set "NASM_PREFIX=%%~dpi"
    ) else (
        echo [X] NASM was not found. Install NASM and/or set NASM_PREFIX environment variable.
        exit /b 1
    )
    echo [^>] Found. NASM_PREFIX was manually set to "!NASM_PREFIX!"
)

echo [^>] Setting up EDK2...
pushd "%EDK2_DIR%"
call edksetup.bat Reconfig
if !errorlevel! neq 0 (
    echo [X] Failed to configure EDK2. Check the output above for errors.
    popd
    exit /b 1
)

set "TARGET_TXT=Conf\target.txt"
(
echo ACTIVE_PLATFORM       = MdeModulePkg/MdeModulePkg.dsc
echo TARGET                = RELEASE
echo TARGET_ARCH           = X64
echo TOOL_CHAIN_TAG        = CLANGPDB
echo MAX_CONCURRENT_THREAD_NUMBER = %NUMBER_OF_PROCESSORS%
echo BUILD_RULE_CONF       = Conf/build_rule.txt
)>"%TARGET_TXT%"

if not exist "BaseTools\" (
    echo [X] Path "BaseTools" is missing. Has the EDK2 source layout changed?
    popd
    exit /b 1
)

pushd "BaseTools"
echo [^>] Compiling EDK2 BaseTools...
call nmake clean
call nmake
if !errorlevel! neq 0 (
    echo [X] Failed to compile BaseTools ^(nmake returned !errorlevel!^)
    popd
    popd
    exit /b 1
)
popd

echo [>] Building EDK2 release libraries...
call build -p MdePkg/MdePkg.dsc -a X64 -b RELEASE -t CLANGPDB -D DISABLE_NEW_DEPRECATED_INTERFACES
if !errorlevel! neq 0 (
    echo [X] Failed to compile MdePkg release libraries
    popd 
    exit /b 1
)

call build -p MdeModulePkg/MdeModulePkg.dsc -a X64 -b RELEASE -t CLANGPDB -D DISABLE_NEW_DEPRECATED_INTERFACES
if !errorlevel! neq 0 (
    echo [X] Failed to compile MdeModulePkg release libraries
    popd 
    exit /b 1
)

echo [>] Building EDK2 debug libraries...
call build -p MdePkg/MdePkg.dsc -a X64 -b DEBUG -t CLANGPDB -D DISABLE_NEW_DEPRECATED_INTERFACES
if !errorlevel! neq 0 (
    echo [X] Failed to compile MdePkg debug libraries
    popd 
    exit /b 1
)

call build -p MdeModulePkg/MdeModulePkg.dsc -a X64 -b DEBUG -t CLANGPDB -D DISABLE_NEW_DEPRECATED_INTERFACES
if !errorlevel! neq 0 (
    echo [X] Failed to compile MdeModulePkg debug libraries
    popd 
    exit /b 1
)

echo [^>] Generating autogen for module.inf...
set "PACKAGES_PATH=%CD%\.."
call build -p bootkit/bootkit.dsc -a X64 -b DEBUG -t CLANGPDB
if !errorlevel! neq 0 (
    echo [X] Failed to generate autogen for DEBUG target
    popd
    exit /b 1
)

call build -p bootkit/bootkit.dsc -a X64 -b RELEASE -t CLANGPDB
if !errorlevel! neq 0 (
    echo [X] Failed to generate autogen for RELEASE target
    popd
    exit /b 1
)

popd

set "MOD_DEP_LIST_DEBUG=bin\bootkit\DEBUG_CLANGPDB\X64\bootkit\bootkit\pandora\OUTPUT\static_library_files.lst"
set "MOD_DEP_LIST_RELEASE=bin\bootkit\RELEASE_CLANGPDB\X64\bootkit\bootkit\pandora\OUTPUT\static_library_files.lst"
more +1 "edk2\%MOD_DEP_LIST_DEBUG%" > "edk2\%MOD_DEP_LIST_DEBUG%.vs"
more +1 "edk2\%MOD_DEP_LIST_RELEASE%" > "edk2\%MOD_DEP_LIST_RELEASE%.vs"

set "PROPS_FILE=edk2.props"
echo ^<?xml version="1.0" encoding="utf-8"?^> > "%PROPS_FILE%"
echo ^<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"^> >> "%PROPS_FILE%"
echo   ^<ImportGroup Label="PropertySheets" /^> >> "%PROPS_FILE%"
echo   ^<PropertyGroup Label="UserMacros"^> >> "%PROPS_FILE%"
echo     ^<EDK2_DIR^>$(ProjectDir)edk2^</EDK2_DIR^> >> "%PROPS_FILE%"
echo   ^</PropertyGroup^> >> "%PROPS_FILE%"
echo   ^<PropertyGroup Condition="'$(Configuration)' == 'Debug'"^> >> "%PROPS_FILE%"
echo     ^<EDK2_LIBS_DIR^>$(EDK2_DIR)\Build\Mde\DEBUG_CLANGPDB\X64^</EDK2_LIBS_DIR^> >> "%PROPS_FILE%"
echo     ^<EDK2_LIBS_DIR2^>$(EDK2_DIR)\Build\MdeModule\DEBUG_CLANGPDB\X64^</EDK2_LIBS_DIR2^> >> "%PROPS_FILE%"
echo     ^<EDK2_AUTOGEN_DIR^>$(EDK2_DIR)\bin\bootkit\DEBUG_CLANGPDB\X64\bootkit\bootkit\pandora\DEBUG^</EDK2_AUTOGEN_DIR^> >> "%PROPS_FILE%"
echo     ^<EDK2_MOD_DEPLIST^>$(EDK2_DIR)\%MOD_DEP_LIST_DEBUG%.vs^</EDK2_MOD_DEPLIST^> >> "%PROPS_FILE%"
echo   ^</PropertyGroup^> >> "%PROPS_FILE%"
echo   ^<PropertyGroup Condition="'$(Configuration)' == 'Release'"^> >> "%PROPS_FILE%"
echo     ^<EDK2_LIBS_DIR^>$(EDK2_DIR)\Build\Mde\RELEASE_CLANGPDB\X64^</EDK2_LIBS_DIR^> >> "%PROPS_FILE%"
echo     ^<EDK2_LIBS_DIR2^>$(EDK2_DIR)\Build\MdeModule\RELEASE_CLANGPDB\X64^</EDK2_LIBS_DIR2^> >> "%PROPS_FILE%"
echo     ^<EDK2_AUTOGEN_DIR^>$(EDK2_DIR)\bin\bootkit\RELEASE_CLANGPDB\X64\bootkit\bootkit\pandora\DEBUG^</EDK2_AUTOGEN_DIR^> >> "%PROPS_FILE%"
echo     ^<EDK2_MOD_DEPLIST^>$(EDK2_DIR)\%MOD_DEP_LIST_RELEASE%.vs^</EDK2_MOD_DEPLIST^> >> "%PROPS_FILE%"
echo   ^</PropertyGroup^> >> "%PROPS_FILE%"
echo   ^<ItemDefinitionGroup /^> >> "%PROPS_FILE%"
echo   ^<ItemGroup /^> >> "%PROPS_FILE%"
echo ^</Project^> >> "%PROPS_FILE%"

echo [^>] Moving AutoGen.c
copy "edk2\bin\bootkit\DEBUG_CLANGPDB\X64\bootkit\bootkit\pandora\DEBUG\AutoGen.c" "bootkit\bootkit\src\autogen\debug\AutoGen.c"
copy "edk2\bin\bootkit\RELEASE_CLANGPDB\X64\bootkit\bootkit\pandora\DEBUG\AutoGen.c" "bootkit\bootkit\src\autogen\release\AutoGen.c"

echo [^>] Created a edk2.props file for Visual Studio %VS_YEAR%

echo [^>] Everything set. Compile the project through Visual Studio.