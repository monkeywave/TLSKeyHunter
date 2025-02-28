#!/bin/bash

# Check if both a path and a symbol name are provided as arguments
if [ -z "$1" ] || [ -z "$2" ]; then
  echo "Usage: $0 <path_to_libs> <symbol_name>"
  exit 1
fi

# Store the path and symbol name
LIB_PATH="$1"
SYMBOL_NAME="$2"

# ANSI escape code for red color
RED='\033[0;31m'
NC='\033[0m' # No Color

# Loop through all libraries in the specified directory
for lib in "$LIB_PATH"/*.a; do
  # Search for the symbol and print lines with matching symbols
  nm -g "$lib" | grep " $SYMBOL_NAME" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    nm -g "$lib" | grep --color=always " $SYMBOL_NAME"
    echo -e "Symbol found in: $lib"
  fi
done