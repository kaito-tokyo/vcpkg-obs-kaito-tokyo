#!/bin/bash

# The MIT License (MIT)
#
# Copyright (c) 2025 Kaito Udagawa
#
# See LICENSE for more information.

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

curl -fsSLo "$basedir/../keys.json" https://apiauth.vcpkg-obs.kaito.tokyo/keys
