
$AllowList = @(
	"CI",
	"COMSPEC",
	"LOCALAPPDATA",
	"PATH",
	"PATHEXT",
	"ProgramData",
	"ProgramFiles",
	"ProgramFiles(x86)",
	"ProgramW6432",
	"SystemDrive",
	"SystemRoot",
	"TEMP",
	"TMP",
	"USERNAME",
	"USERPROFILE",
	"VCPKG_BINARY_SOURCES",
	"VCPKG_ROOT"
)

Get-ChildItem Env: | ForEach-Object {
	if ($AllowList -notcontains $_.Name -and $_.Name -notlike "GITHUB_*" -and $_.Name -notlike "RUNNER_*") {
		Remove-Item $_.PSPath -Force
	}
}
