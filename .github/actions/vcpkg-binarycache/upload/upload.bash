#!/bin/bash

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# Publishes the binary packages the vcpkg files provider staged during the
# build. Their provenance is attested separately and kept by GitHub.
#
# The runner authenticates with a GitHub Actions id token, which apiauth trades
# for a short lived master token, so nothing long lived is kept in the
# repository secrets.

set -euo pipefail
shopt -s nullglob

: "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:?id-token: write is required}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?id-token: write is required}"
: "${ARTIFACT_DIRECTORY:?}"

# These are constants rather than inputs because each one has to agree with a
# value compiled into a worker: APIAUTH_URL doubles as the audience apiauth
# verifies the id token against, and the master token apiauth issues is stamped
# with the readwrite audience. Pointing either at another deployment without
# redeploying both workers only produces 401s.
readonly APIAUTH_URL=https://apiauth.vcpkg-obs.kaito.tokyo
readonly READWRITE_URL=https://readwrite.vcpkg-obs.kaito.tokyo

id_token=$(
  curl -fsS -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
    "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=$APIAUTH_URL" | jq -er .value
)
printf '::add-mask::%s\n' "$id_token"

master_token=$(
  curl -fsS -X POST -H "Authorization: Bearer $id_token" \
    "$APIAUTH_URL/oidc/master-token"
)
printf '::add-mask::%s\n' "$master_token"

access_token=$(
  curl -fsS -X POST -d "master_token=$master_token" "$READWRITE_URL/token"
)
printf '::add-mask::%s\n' "$access_token"

# The files provider lays packages out as <abi first two chars>/<abi>.zip, so
# the file name is already the {sha} the binary cache is keyed by.
#
# `separator` emits `next` between requests only; a trailing one makes curl bail
# out with "no URL specified".
separator=
for archive in "$ARTIFACT_DIRECTORY"/*/*.zip; do
  abi=$(basename "$archive" .zip)
  echo "- $abi" >&2

  presigned_url=$(
    curl -fsS -X POST -H "Authorization: Bearer $access_token" \
      "$READWRITE_URL/binarycache/$abi" | jq -er .presignedUrl
  )

  printf '%surl = "%s"\nupload-file = "%s"\nheader = "Content-Type: application/zip"\nheader = "Cache-Control: public, max-age=86400"\n' \
    "$separator" "$presigned_url" "$archive"
  separator=$'next\n'
done | curl -Z -fL -K -
