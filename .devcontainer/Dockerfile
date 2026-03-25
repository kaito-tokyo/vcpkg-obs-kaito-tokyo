# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# busybox-scratch: Hack for Dev Container
FROM --platform=linux/amd64 busybox:1.37.0-glibc AS busybox-scratch
RUN rm -rf /bin /etc /home /lib /lib64 /root /sbin /usr /var || true

FROM --platform=linux/amd64 scratch AS pure-scratch

# noble-minbase: Bootstraps minbase noble
FROM ubuntu:noble-20260217 AS noble-minbase

RUN <<'EOT' DEBIAN_FRONTEND=noninteractive bash -euo pipefail -O nullglob
  dependencies=(
    ca-certificates=20240203
    debootstrap=1.0.134ubuntu1
  )
  apt-get update
  apt-get install -y --no-install-recommends "${dependencies[@]}"
  rm -rf /var/lib/apt/lists/*
EOT

RUN debootstrap --variant=minbase --include=ca-certificates noble /rootfs http://archive.ubuntu.com/ubuntu/

# obs-build-deps: Installs OBS build dependencies
FROM busybox-scratch AS obs-build-deps

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

COPY --from=noble-minbase /rootfs /

COPY <<'EOF' /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
EOF

ADD --chmod=644 https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=get&search=0xBC7345F522079769F5BBE987EFC71127F425E228 /etc/apt/keyrings/obsproject.asc

COPY <<'EOF' /etc/apt/sources.list.d/obsproject.list
deb [signed-by=/etc/apt/keyrings/obsproject.asc] https://ppa.launchpadcontent.net/obsproject/obs-studio/ubuntu noble main
EOF

RUN <<'EOT' DEBIAN_FRONTEND=noninteractive bash -euo pipefail -O nullglob
  dependencies=(
    build-essential=12.10ubuntu1
    cmake=3.28.3-1build7
    curl=8.5.0-2ubuntu10
    file=1:5.45-3build1
    git=1:2.43.0-1ubuntu7
    jq=1.7.1-3build1
    libgles2-mesa-dev=24.0.5-1ubuntu1
    qt6-svg-dev=6.4.2-4ubuntu3
    libsimde-dev=0.7.2-6
    ninja-build=1.11.1-2
    obs-studio=32.1.0-0obsproject1~noble
    pkg-config=1.8.1-2build1
    qt6-base-dev=6.4.2+dfsg-21.1build5
    qt6-base-private-dev=6.4.2+dfsg-21.1build5
    sudo=1.9.15p5-3ubuntu5
    tar=1.35+dfsg-3build1
    unzip=6.0-28ubuntu4
    zip=3.0-13build1
  )
  apt-get update
  apt-get install -y --no-install-recommends "${dependencies[@]}"
  rm -rf /var/lib/apt/lists/*
EOT

# bootstrap-vcpkg: Clone and bootstrap vcpkg
FROM obs-build-deps AS bootstrap-vcpkg
ENV VCPKG_ROOT=/usr/local/vcpkg
ENV VCPKG_DOWNLOADS=/usr/local/vcpkg-downloads
COPY vcpkg_default_registry_baseline.txt /usr/local/vcpkg_default_registry_baseline.txt
RUN <<'EOT' bash -euo pipefail -O nullglob
  git clone --filter=blob:none --no-checkout https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT}"
  cd "${VCPKG_ROOT}"
  git checkout "$(< /usr/local/vcpkg_default_registry_baseline.txt)"
  mkdir -p "${VCPKG_DOWNLOADS}"
  "${VCPKG_ROOT}/bootstrap-vcpkg.sh" -disableMetrics
  groupadd -g 999 vcpkg
  chgrp -R vcpkg "${VCPKG_ROOT}"
  chmod -R ug=rwX,o=rX "${VCPKG_ROOT}"
EOT

# final: Final image for Dev Container and GitHub Actions runner
FROM bootstrap-vcpkg AS final

RUN <<'EOT' bash -euo pipefail -O nullglob
	groupadd -g 1000 vscode
	useradd -u 1000 -g vscode -m vscode -G vcpkg -s /bin/bash
	groupadd -g 1001 runner
	useradd -u 1001 -g runner -m runner -G vcpkg -s /bin/bash
EOT

COPY --chmod=400 <<'EOF' /etc/sudoers.d/vscode
vscode ALL=(ALL) NOPASSWD: ALL
EOF

USER vscode
