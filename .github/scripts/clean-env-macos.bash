# SPDX-FileCopyrightText: 2026 Kaito Udagawa <umireon@kaito.tokyo>
#
# SPDX-License-Identifier: Apache-2.0

# file: .github/scripts/clean-env-macos.bash
# author: Kaito Udagawa <umireon@kaito.tokyo>
# version: 1.0.0
# date: 2026-03-31

filter_env_macos() {
  local names=($(compgen -e))
  local name
  for name in "${names[@]}"; do
    case "$name" in
    # Pattern
    ACTIONS_* | CCACHE_* | GIT_* | GITHUB_* | PLUGIN_* | RUNNER_*) ;;
    # Common
    CI | HOME | LANG | LC_ALL | LC_CTYPE | LOGNAME | PATH | PSModulePath | SHELL | TERM | TMPDIR | USER | XDG_CONFIG_HOME) ;;
    # macOS
    DEVELOPER_DIR | ImageOS | ImageVersion | XPC_FLAGS | XPC_SERVICE_NAME) ;;
    # Workflow-specific
    VCPKG_BINARY_SOURCES | VCPKG_ROOT) ;;
    *) unset -v "$name" 2>/dev/null || true ;;
    esac
  done
}
filter_env_macos
unset -f filter_env_macos
