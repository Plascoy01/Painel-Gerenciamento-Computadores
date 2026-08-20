#!/bin/bash

# PLASCOV Executable Wrapper
# This script activates the virtual environment and runs the PLASCOV scanner
cd /home/crypt01lord/Documentos/plascoy source/
# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Activate the virtual environment
source "$SCRIPT_DIR/plascoy_env/bin/activate"

# Run the Python script with all arguments passed to this script
python "$SCRIPT_DIR/plascoy.py" "$@"
