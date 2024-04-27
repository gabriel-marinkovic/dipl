#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$SCRIPT_DIR"

# Set the repository URL and directory name
REPO_URL="https://github.com/DynamoRIO/dynamorio.git"
REPO_DIR="$SCRIPT_DIR/DynamoRIO_src"
INSTALL_DIR="$SCRIPT_DIR/DynamoRIO"

rm -rf INSTALL_DIR

if [[ ! -d "$REPO_DIR" ]]; then
  git clone -j4 \
  	--branch master \
  	--depth 1 --recurse-submodules --shallow-submodules \
  	"$REPO_URL" "$REPO_DIR"
else
  echo "Repository directory already exists. Skipping clone."
fi

cd "$REPO_DIR"
rm -rf build
mkdir build

cmake -Bbuild "$@" -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" .
cmake --build build --target install -j
