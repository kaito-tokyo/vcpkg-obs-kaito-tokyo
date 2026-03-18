filter_env_macos() {
	local names=($(compgen -e))
	local name

	for name in "${names[@]}"; do

		[[ "$name" =~ ^(GITHUB_|RUNNER_) ]] && continue
		case "$name" in
		# Common
		CI | HOME | LANG | LC_ALL | LC_CTYPE | LOGNAME | PATH | PSModulePath | SHELL | TERM | TMPDIR | USER | XDG_CONFIG_HOME) ;;
		# macOS
		DEVELOPER_DIR | ImageOS | ImageVersion | XPC_FLAGS | XPC_SERVICE_NAME) ;;
		# Workflow-specific
		VCPKG_BINARY_SOURCES | VCPKG_ROOT) ;;
		*) unset -v "$name" 2>/dev/null ;;
		esac
	done
}
filter_env_macos
unset -f filter_env_macos
