package main

import (
	"regexp"
	"testing"

	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
	"github.com/yuskesh/spinel-bpf-mlir/internal/version"
)

// formBuildArgs is the build tag used when a test runs `go build` on spinelbpf (the public form).
var formBuildArgs = []string{}

// versionFlagWant is the expected `--version` output (the public form — the bpf-mlir v1.23.0 source release and
// go-bpf-mlir v0.21.0).
var versionFlagWant = regexp.MustCompile(`^spinel-bpf-mlir v0\.11\.0 \(commit ([0-9a-f]{12}(\+dirty)?|unknown)\)
bpf-mlir v1\.23\.0 \(commit 1a58c8d6; Go packages github\.com/yuskesh/go-bpf-mlir v0\.21\.0, go\.mod require\)
bml v0\.2\.0 \(commit 8ad2e0b\)
spinel 0d58c397
ebpf-compile: bpf-mlir v1\.23\.0 \(commit 1a58c8d6ef57262dfaf68989c370925caddc66f9\)
$`)

// publicVersionText composes the 5 lines of the public form's `spinelbpf --version` from the pin and version constants.
// In the development tree the public form's TestVersionFlag cannot pass (go.mod and ebpf-compile are in the development
// form), so this is where we check that the expected regular expression does not disagree with the constants. The real
// output is checked by TestVersionFlag in the public tree.
func publicVersionText(ver, compilerVersion, compilerCommit, module, moduleVersion string) string {
	return "spinel-bpf-mlir " + ver + " (commit 0123456789ab)\n" +
		"bpf-mlir " + compilerVersion + " (commit " + compilerCommit[:8] + "; Go packages " + module + " " + moduleVersion + ", go.mod require)\n" +
		"bml " + toolchain.ReleaseBMLVersion + " (commit " + toolchain.ReleaseBMLSourceCommit[:7] + ")\n" +
		"spinel " + version.Spinel + "\n" +
		"ebpf-compile: bpf-mlir " + compilerVersion + " (commit " + compilerCommit + ")\n"
}

// TestPublicVersionFlagWant: the public form's versionFlagWant matches the `--version` composed from the version and the
// constants in pin_release.go. (When ReleaseGoModuleVersion was once raised, the expected v0.18.0 was left behind; this
// test makes the gate's public stage catch such an omission.)
func TestPublicVersionFlagWant(t *testing.T) {
	got := publicVersionText(version.Version, toolchain.ReleaseCompilerVersion, toolchain.ReleaseCompilerCommit, toolchain.ReleaseGoModule, toolchain.ReleaseGoModuleVersion)
	t.Logf("composed --version:\n%s", got)
	if !versionFlagWant.MatchString(got) {
		t.Errorf("versionFlagWant does not match the --version composed from the release pins — update form_public_test.go with the pin:\n%s", got)
	}
}
