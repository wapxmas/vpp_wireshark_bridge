#!/bin/bash

# =========================================================================
# VPP-Wireshark Extcap Bridge
# 
# This script serves as a bridge between VPP (Vector Packet Processing) and
# Wireshark, allowing Wireshark to capture packets from VPP.
# 
# Usage: vpp_extcap_bridge.sh [Wireshark extcap arguments]
# 
# NOTE: This script uses hardcoded paths since it's called directly by
# Wireshark as an extcap utility. Environment variables are not available.
# =========================================================================

# -------------------------------------------------------------------------
# Configuration (Hardcoded paths - modify these as needed)
# -------------------------------------------------------------------------
# Define the exact path to the Python bridge script
PY_BRIDGE_SCRIPT_DIR="/Users/user/work/vpp_extcap_bridge"
VENV_DIR="${PY_BRIDGE_SCRIPT_DIR}/.env/bin"

# Define connection parameters
VPP_HOST="192.168.137.75"
VPP_PORT="8080"

# Wireshark connection parameters
# UNCOMMENT the following lines to set custom Wireshark IP and/or port
# WIRESHARK_IP="127.0.0.1"
# WIRESHARK_PORT="5000"

# -------------------------------------------------------------------------
# Signal Handling and Cleanup
# -------------------------------------------------------------------------
# Global variable to store Python process PID
PYTHON_PID=""

# Cleanup function to ensure proper termination
cleanup() {
    echo "Received termination signal. Cleaning up..."
    
    # Kill Python process if it exists
    if [ -n "${PYTHON_PID}" ] && kill -0 ${PYTHON_PID} 2>/dev/null; then
        echo "Terminating Python process (PID: ${PYTHON_PID})"
        kill -TERM ${PYTHON_PID} 2>/dev/null
        
        # Increase wait time to 2 seconds
        for i in {1..4}; do
            sleep 0.5
            if ! kill -0 ${PYTHON_PID} 2>/dev/null; then
                break
            fi
        done
        
        # Force kill if still running
        if kill -0 ${PYTHON_PID} 2>/dev/null; then
            echo "Force killing Python process"
            kill -9 ${PYTHON_PID} 2>/dev/null
        fi
    fi
    
    # Deactivate virtual environment if active
    if type deactivate > /dev/null 2>&1; then
        deactivate
    fi
    
    # Return to original directory
    cd "${ORIG_DIR}"
    
    echo "Cleanup complete. Exiting."
    exit 0
}

# Set up signal traps
trap cleanup SIGINT SIGTERM SIGHUP

# -------------------------------------------------------------------------
# Script Execution
# -------------------------------------------------------------------------
# Save current directory
ORIG_DIR="$(pwd)"

# Validate script directory existence
if [ ! -d "${PY_BRIDGE_SCRIPT_DIR}" ]; then
    echo "ERROR: Script directory not found: ${PY_BRIDGE_SCRIPT_DIR}"
    exit 1
fi

# Change to script directory
if ! cd "${PY_BRIDGE_SCRIPT_DIR}"; then
    echo "ERROR: Failed to change to script directory"
    exit 1
fi

# Validate virtual environment
if [ ! -f "${VENV_DIR}/activate" ]; then
    echo "ERROR: Virtual environment not found at ${VENV_DIR}"
    echo "Please ensure the virtual environment is set up correctly."
    cd "${ORIG_DIR}"
    exit 1
fi

# Validate main Python script
MAIN_SCRIPT="${PY_BRIDGE_SCRIPT_DIR}/vpp_extcap_bridge.py"
if [ ! -f "${MAIN_SCRIPT}" ]; then
    echo "ERROR: Main Python script not found: ${MAIN_SCRIPT}"
    cd "${ORIG_DIR}"
    exit 1
fi

# -------------------------------------------------------------------------
# Execute Python Bridge
# -------------------------------------------------------------------------
# Activate virtual environment
if ! source "${VENV_DIR}/activate"; then
    echo "ERROR: Failed to activate Python virtual environment"
    cd "${ORIG_DIR}"
    exit 1
fi

# Check if python3 or python exists
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "ERROR: Neither python3 nor python commands are available"
    deactivate
    cd "${ORIG_DIR}"
    exit 1
fi

# Prepare command line arguments
CMD_ARGS="--vpp-host \"${VPP_HOST}\" --vpp-port ${VPP_PORT}"

# Add Wireshark IP and port parameters if defined
if [ -n "${WIRESHARK_IP}" ]; then
    CMD_ARGS="${CMD_ARGS} --wireshark-ip \"${WIRESHARK_IP}\""
fi

if [ -n "${WIRESHARK_PORT}" ]; then
    CMD_ARGS="${CMD_ARGS} --wireshark-port ${WIRESHARK_PORT}"
fi

# Run Python script in background and capture its PID
eval "${PYTHON_CMD} vpp_extcap_bridge.py ${CMD_ARGS} $@" &
PYTHON_PID=$!

# Wait for the Python process to complete
wait ${PYTHON_PID}
PY_ERROR=$?

# Reset the PID since the process has completed
PYTHON_PID=""

# Always attempt to deactivate the virtual environment
deactivate

# Report any Python errors
if [ ${PY_ERROR} -ne 0 ]; then
    echo "Python process exited with error code: ${PY_ERROR}"
    cd "${ORIG_DIR}"
    exit ${PY_ERROR}
fi

# -------------------------------------------------------------------------
# Cleanup
# -------------------------------------------------------------------------
# Return to original directory
cd "${ORIG_DIR}"

exit 0 