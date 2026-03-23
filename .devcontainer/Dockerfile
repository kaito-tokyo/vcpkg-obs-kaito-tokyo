# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

ARG ARG_BASE_IMAGE=mcr.microsoft.com/devcontainers/base:ubuntu-24.04

FROM --platform=linux/amd64 ${ARG_BASE_IMAGE} AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ADD --chmod=644 https://keyserver.ubuntu.com/pks/lookup?fingerprint=on&op=get&search=0xBC7345F522079769F5BBE987EFC71127F425E228 /etc/apt/keyrings/obsproject.asc

RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/obsproject.asc] https://ppa.launchpadcontent.net/obsproject/obs-studio/ubuntu noble main" > /etc/apt/sources.list.d/obsproject.list && \
    apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    file \
    git \
    jq \
    libgles2-mesa-dev \
    libqt6svg6-dev \
    libsimde-dev \
    ninja-build \
    obs-studio \
    pkg-config \
    qt6-base-dev \
    qt6-base-private-dev \
    tar \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

ARG ARG_USERNAME=vscode
RUN case "${ARG_USERNAME}" in \
    runner) useradd -u 1001 runner && mkdir -p /home/runner && chown -R runner:runner /home/runner && chmod -R u=rwX,go=rX /home/runner ;; \
    vscode) mkdir -p /workspaces && chown -R vscode:vscode /workspaces && chmod -R u=rwX,go=rX /workspaces ;; \
    esac

ENV VCPKG_ROOT=/home/${ARG_USERNAME}/vcpkg
ARG ARG_VCPKG_DEFAULT_REGISTRY_BASELINE=master

USER ${ARG_USERNAME}
RUN git clone --filter=blob:none --no-checkout https://github.com/microsoft/vcpkg.git "${VCPKG_ROOT}" && \
    cd "${VCPKG_ROOT}" && \
    git checkout "${ARG_VCPKG_DEFAULT_REGISTRY_BASELINE}" && \
    "${VCPKG_ROOT}/bootstrap-vcpkg.sh" -disableMetrics
