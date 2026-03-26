#!/bin/bash

# The MIT License (MIT)
#
# Copyright (c) 2025 Kaito Udagawa
#
# See LICENSE for more information.

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

keyname="$(date +%Y%m)${1-}"

set -f
keypair=($(node "$basedir/generate-secret.js" "$keyname"))
set +f

printf 'SECRET_KEY_JSON:%s\n' "${keypair[0]}"

printf 'Proceed? (y/N) '
read -r answer

if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
	echo "Aborted."
	exit 1
fi

npx wrangler secret put SECRET_KEY_JSON <<< "${keypair[0]}"
