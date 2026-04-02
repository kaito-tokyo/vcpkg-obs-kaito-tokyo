#!/bin/bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

pushd "$basedir/apiauth"
npm install
scripts/renew-keys.bash
npx wrangler deploy
popd

pushd "$basedir/readwrite"
npm install
scripts/fetch-jwks.bash
scripts/renew-keys.bash
npx wrangler deploy
popd

echo "All done."
