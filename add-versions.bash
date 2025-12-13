#!/bin/bash

PACKAGE_NAMES=($(ls ports))

vcpkg --x-builtin-ports-root=./ports --x-builtin-registry-versions-dir=./versions x-add-version --verbose --overwrite-version "${PACKAGE_NAMES[@]}"
