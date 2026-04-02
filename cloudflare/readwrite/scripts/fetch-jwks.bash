#!/bin/bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

curl -fsSLo "$basedir/../keys.json" https://apiauth.vcpkg-obs.kaito.tokyo/keys
