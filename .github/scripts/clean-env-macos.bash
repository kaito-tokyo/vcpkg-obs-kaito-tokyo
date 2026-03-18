filter_env_macos() {
	local names=($(compgen -e))
	local name

	for name in "${names[@]}"; do
		[[ "$name" =~ ^(GITHUB_|RUNNER_) ]] && continue
		case "$name" in
		CI | HOME | PATH | SHELL | TERM | TMPDIR | USER | LOGNAME | LANG | LC_ALL) ;;
		DEVELOPER_DIR | XPC_FLAGS | XPC_SERVICE_NAME) ;;
		VCPKG_BINARY_SOURCES | VCPKG_ROOT) ;;
		*) unset -v "$name" 2>/dev/null ;;
		esac
	done
}
filter_env_macos
unset -f filter_env_macos
