#!/bin/bash
set -eo pipefail

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

"$DIR/build/dynamorio/_deps/dynamorio-build/bin64/drrun" \
    -c build/src/libclient.so \
    -- "build/example/$1"
