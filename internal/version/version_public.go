package version

import "github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"

// BpfMLIRModule is the module of bpf-mlir's Go packages in the public form — go-bpf-mlir, copied from the commit of
// bpf-mlir's source release.
const BpfMLIRModule = toolchain.ReleaseGoModule

// bpfMLIRLine is the bpf-mlir line of `--version` up to its closing parenthesis — the compiler's source release, and the
// Go packages' module with its version from the build information.
func bpfMLIRLine(ver string) string {
	return toolchain.ReleaseCompilerVersion + " (commit " + toolchain.ReleaseCompilerCommit[:8] + "; Go packages " + BpfMLIRModule + " " + ver + ", go.mod require"
}

// bmlLine is the bml line of `--version`: the public bpf-mlir-loader release and the first seven digits of its SOURCE_VERSION
// source_commit, which is the bml the public form links. It does not use BML, the development gitlink, which may differ
// from the release by the declared changes.
func bmlLine() string {
	return toolchain.ReleaseBMLVersion + " (commit " + toolchain.ReleaseBMLSourceCommit[:7] + ")"
}
