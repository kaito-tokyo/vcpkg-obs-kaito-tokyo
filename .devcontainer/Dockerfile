# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed

# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# noble-minbase: Bootstraps minbase noble.
FROM --platform=linux/amd64 ubuntu:noble-20260217 AS deboostrap

RUN <<'EOT' bash -euo pipefail -O nullglob
# Pinning at the available version on 2006-03-25
dependencies=(
  ca-certificates=20240203
  debootstrap=1.0.134ubuntu1
)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${dependencies[@]}"
rm -rf /var/lib/apt/lists/*
EOT

RUN <<'EOT' bash -euo pipefail -O nullglob
debootstrap --variant=minbase --include=ca-certificates noble /rootfs http://archive.ubuntu.com/ubuntu/
rm -rf /rootfs/var/lib/apt/lists/* /rootfs/var/cache/apt/archives/*
EOT

# obs-deps: Installs dependencies for building OBS plugins.
FROM scratch AS minbase

COPY --from=deboostrap /rootfs /

COPY <<'EOF' /etc/apt/apt.conf.d/docker-clean
DPkg::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };
APT::Update::Post-Invoke { "rm -f /var/cache/apt/archives/*.deb /var/cache/apt/archives/partial/*.deb /var/cache/apt/*.bin || true"; };
Dir::Cache::pkgcache ""; Dir::Cache::srcpkgcache "";
EOF

COPY <<'EOF' /etc/apt/apt.conf.d/docker-no-languages
Acquire::Languages "none";
EOF

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

CMD ["/bin/bash"]

# obs-deps: Installs dependencies for building OBS plugins.
FROM minbase AS obs-deps

RUN ["install", "-d", "/etc/apt/keyrings"]

COPY <<'EOF' /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse
EOF

COPY obsproject.asc /etc/apt/keyrings/obsproject.asc

COPY <<'EOF' /etc/apt/sources.list.d/obsproject.list
deb [signed-by=/etc/apt/keyrings/obsproject.asc] https://ppa.launchpadcontent.net/obsproject/obs-studio/ubuntu noble main
EOF

RUN <<'EOT' bash -euo pipefail -O nullglob
# Pinning at the latest versions on noble, and let it detect if any changes occurred on noble repository.
dependencies=(
  build-essential=12.10ubuntu1
  cmake=3.28.3-1build7
  curl=8.5.0-2ubuntu10
  file=1:5.45-3build1
  git=1:2.43.0-1ubuntu7
  jq=1.7.1-3build1
  libgles2-mesa-dev=24.0.5-1ubuntu1
  libsimde-dev=0.7.2-6
  ninja-build=1.11.1-2
  obs-studio=32.1.0-0obsproject1~noble
  pkg-config=1.8.1-2build1
  qt6-base-dev=6.4.2+dfsg-21.1build5
  qt6-base-private-dev=6.4.2+dfsg-21.1build5
  qt6-svg-dev=6.4.2-4ubuntu3
  sudo=1.9.15p5-3ubuntu5
  tar=1.35+dfsg-3build1
  tini=0.19.0-1
  unzip=6.0-28ubuntu4
  zip=3.0-13build1
)
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${dependencies[@]}"
rm -rf /var/lib/apt/lists/*
EOT

# bootstrap-vcpkg: Installs and bootstraps vcpkg.
FROM obs-deps AS bootstrap-vcpkg

ENV VCPKG_ROOT=/usr/local/vcpkg VCPKG_DOWNLOADS=/usr/local/vcpkg-downloads

COPY vcpkg_default_registry_baseline.txt /usr/local/vcpkg_default_registry_baseline.txt

RUN <<'EOT' bash -euo pipefail -O nullglob
install -d "${VCPKG_DOWNLOADS}"
git clone --filter=blob:none --no-checkout https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT}"
cd "${VCPKG_ROOT}"
git checkout "$(< /usr/local/vcpkg_default_registry_baseline.txt)"
"${VCPKG_ROOT}/bootstrap-vcpkg.sh" -disableMetrics
groupadd -g 999 vcpkg
chgrp -R vcpkg "${VCPKG_ROOT}" "${VCPKG_DOWNLOADS}"
chmod -R ug=rwX,o=rX "${VCPKG_ROOT}" "${VCPKG_DOWNLOADS}"
EOT

# final: Adds users for Dev Container and GitHub Actions.
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

CMD ["/bin/bash"]

USER vscode
