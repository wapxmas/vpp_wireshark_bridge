@echo off
setlocal EnableExtensions

:: =========================================================================
:: VPP-Wireshark Extcap Bridge
:: 
:: This script serves as a bridge between VPP (Vector Packet Processing) and
:: Wireshark, allowing Wireshark to capture packets from VPP.
:: 
:: Usage: vpp_extcap_bridge.bat [Wireshark extcap arguments]
:: 
:: NOTE: This script uses hardcoded paths since it's called directly by
:: Wireshark as an extcap utility. Environment variables are not available.
:: =========================================================================

:: -------------------------------------------------------------------------
:: Configuration (Hardcoded paths - modify these as needed)
:: -------------------------------------------------------------------------
:: Define the exact path to the Python bridge script
set "PY_BRIDGE_SCRIPT_DIR=C:\Users\user\work\wireshark_extcap\vpp_extcap_bridge"
set "VENV_DIR=%PY_BRIDGE_SCRIPT_DIR%\.env\Scripts"

:: Define connection parameters
set "VPP_HOST=192.168.137.75"
set "VPP_PORT=8080"

:: Wireshark connection parameters
:: UNCOMMENT the following lines to set custom Wireshark IP and/or port
rem set "WIRESHARK_IP=127.0.0.1"
rem set "WIRESHARK_PORT=5000"

:: -------------------------------------------------------------------------
:: Script Execution
:: -------------------------------------------------------------------------
:: Save current directory
pushd "%CD%"

:: Validate script directory existence
if not exist "%PY_BRIDGE_SCRIPT_DIR%" (
    echo ERROR: Script directory not found: "%PY_BRIDGE_SCRIPT_DIR%"
    popd & exit /b 1
)

:: Change to script directory
cd /D "%PY_BRIDGE_SCRIPT_DIR%" || (
    echo ERROR: Failed to change to script directory
    popd & exit /b 1
)

:: Validate virtual environment
if not exist "%VENV_DIR%\activate.bat" (
    echo ERROR: Virtual environment not found at "%VENV_DIR%"
    echo Please ensure the virtual environment is set up correctly.
    popd & exit /b 1
)

:: Validate main Python script
set "MAIN_SCRIPT=%PY_BRIDGE_SCRIPT_DIR%\vpp_extcap_bridge.py"
if not exist "%MAIN_SCRIPT%" (
    echo ERROR: Main Python script not found: "%MAIN_SCRIPT%"
    popd & exit /b 1
)

:: -------------------------------------------------------------------------
:: Execute Python Bridge
:: -------------------------------------------------------------------------
:: Activate virtual environment
call "%VENV_DIR%\activate.bat" || (
    echo ERROR: Failed to activate Python virtual environment
    popd & exit /b 1
)

:: Prepare command line arguments
set "CMD_ARGS=--vpp-host "%VPP_HOST%" --vpp-port %VPP_PORT%"

:: Add Wireshark IP and port parameters if defined
if defined WIRESHARK_IP (
    set "CMD_ARGS=%CMD_ARGS% --wireshark-ip "%WIRESHARK_IP%""
)
if defined WIRESHARK_PORT (
    set "CMD_ARGS=%CMD_ARGS% --wireshark-port %WIRESHARK_PORT%"
)

:: Run Python script with error handling
python vpp_extcap_bridge.py %CMD_ARGS% %*
set /a py_error=%errorlevel%

:: Always attempt to deactivate the virtual environment
call "%VENV_DIR%\deactivate.bat"

:: Report any Python errors
if %py_error% neq 0 (
    popd & exit /b %py_error%
)

:: -------------------------------------------------------------------------
:: Cleanup
:: -------------------------------------------------------------------------
:: Return to original directory
popd

endlocal
exit /b 0
