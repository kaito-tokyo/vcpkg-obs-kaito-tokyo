filter_env_ubuntu() {
	local names=($(compgen -e))
	local name

	for name in "${names[@]}"; do
		[[ "$name" =~ ^(GITHUB_|RUNNER_) ]] && continue
		case "$name" in
		CI | HOME | PATH | SHELL | TERM | TMPDIR | USER | LOGNAME | LANG | LC_ALL) ;;
		DEBIAN_FRONTEND ) ;;
		VCPKG_BINARY_SOURCES | VCPKG_ROOT) ;;
		*) unset -v "$name" 2>/dev/null ;;
		esac
	done
}
filter_env_ubuntu
unset -f filter_env_ubuntu
