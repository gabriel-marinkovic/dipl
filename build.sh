#!/bin/bash
set -eo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
BUILD_DIR="$DIR/build"
DYNAMORIO_BUILD_DIR="$BUILD_DIR/dynamorio"
DYNAMORIO_DIR="$DYNAMORIO_BUILD_DIR/_deps/dynamorio-build/cmake"

if [ "$1" == "force" ]; then
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
fi
mkdir -p "$BUILD_DIR"

(
    mkdir -p "$DYNAMORIO_BUILD_DIR"
    cd "$DYNAMORIO_BUILD_DIR"
    if [ ! -d "$DYNAMORIO_DIR" ]; then
        cmake -DBUILD_DYNAMORIO=ON ../..
        make -j
    fi
    if [ ! -d "$DYNAMORIO_DIR" ]; then
        echo "Failed to build DynamoRIO. Can't find DynamoRIO_DIR: '$DYNAMORIO_DIR'"
        exit 1
    fi
)

(
    cd "$BUILD_DIR"
    cmake \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DDynamoRIO_DIR="$DYNAMORIO_DIR" \
        ..
    make -j
)
