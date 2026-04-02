# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: .github/scripts/clean-env-ubuntu.bash
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.2
# date: 2026-04-02

filter_env_ubuntu() {
  local names
  mapfile -t names < <(compgen -e)

  local name
  for name in "${names[@]}"; do
    case "$name" in
    # Pattern
    ACTIONS_* | CCACHE_* | GIT_* | GITHUB_* | PLUGIN_* | RUNNER_*) ;;
    # Common
    CI | HOME | LANG | LC_ALL | LC_CTYPE | LOGNAME | PATH | PSModulePath | SHELL | TERM | TMPDIR | USER | XDG_CONFIG_HOME) ;;
    # Ubuntu
    DEBIAN_FRONTEND | ImageOS | ImageVersion | XDG_RUNTIME_DIR) ;;
    # Workflow-specific
    VCPKG_BINARY_SOURCES | VCPKG_ROOT | VCPKG_TARGET_TRIPLET) ;;
    *) unset -v "$name" 2>/dev/null || true ;;
    esac
  done
}
filter_env_ubuntu
unset -f filter_env_ubuntu
