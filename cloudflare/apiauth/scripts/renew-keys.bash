#!/bin/bash

set -euo pipefail

basedir=$(cd "$(dirname "$0")" && pwd)

set -f
keypair=($(node "$basedir/generate-keypair.js"))
set +f

printf 'PRIVATE_KEY_HEX:%s\nPUBLIC_KEY_JSON:%s\n' "${keypair[0]}" "${keypair[1]}"

printf 'Proceed? (y/N) '
read -r answer

if [[ "$answer" != "y" && "$answer" != "Y" ]]; then
	echo "Aborted."
	exit 1
fi

npx wrangler secret put PRIVATE_KEY_HEX <<< "${keypair[0]}"
npx wrangler secret put PUBLIC_KEY_JSON <<< "${keypair[1]}"
