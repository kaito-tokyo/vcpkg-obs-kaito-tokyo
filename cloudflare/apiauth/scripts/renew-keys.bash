#!/bin/bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

keyname="$(date +%Y%m)${1-}"

set -f
keypair=()
while IFS= read -r line; do
  keypair+=("$line")
done < <(node "$basedir/generate-keypair.js" "$keyname")
set +f

printf 'PRIVATE_KEY_JSON:%s\nPUBLIC_KEY_JSON:%s\n' "${keypair[0]}" "${keypair[1]}"

printf 'Proceed? (y/N) '
read -r answer

if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
  echo "Aborted."
  exit 1
fi

npx wrangler secret put PRIVATE_KEY_JSON <<<"${keypair[0]}"
echo "{\"keys\":[${keypair[1]}]}" >"$basedir/../assets/keys"
