package main

import (
	"regexp"
	"testing"

	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
	"github.com/yuskesh/spinel-bpf-mlir/internal/version"
)

var formBuildArgs = []string{}

var versionFlagWant = regexp.MustCompile(`^spinel-bpf-mlir v0\.9\.0 \(commit ([0-9a-f]{12}(\+dirty)?|unknown)\)
bpf-mlir v1\.21\.0 \(commit 41b18856; Go packages github\.com/yuskesh/go-bpf-mlir v0\.19\.0, go\.mod require\)
bml v0\.1\.0 \(commit 41ec56f\)
spinel 086d514d
ebpf-compile: bpf-mlir v1\.21\.0 \(commit 41b188568cb36a15d4c185d5f72027267b3fa544\)
$`)

func publicVersionText(ver, compilerVersion, compilerCommit, module, moduleVersion string) string {
	return "spinel-bpf-mlir " + ver + " (commit 0123456789ab)\n" +
		"bpf-mlir " + compilerVersion + " (commit " + compilerCommit[:8] + "; Go packages " + module + " " + moduleVersion + ", go.mod require)\n" +
		"bml " + toolchain.ReleaseBMLVersion + " (commit " + version.BML + ")\n" +
		"spinel " + version.Spinel + "\n" +
		"ebpf-compile: bpf-mlir " + compilerVersion + " (commit " + compilerCommit + ")\n"
}

func TestPublicVersionFlagWant(t *testing.T) {
	got := publicVersionText(version.Version, toolchain.ReleaseCompilerVersion, toolchain.ReleaseCompilerCommit, toolchain.ReleaseGoModule, toolchain.ReleaseGoModuleVersion)
	t.Logf("composed --version:\n%s", got)
	if !versionFlagWant.MatchString(got) {
		t.Errorf("versionFlagWant does not match the --version composed from the release pins — update form_public_test.go with the pin:\n%s", got)
	}
}
