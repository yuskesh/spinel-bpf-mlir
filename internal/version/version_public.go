package version

import "github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"

const BpfMLIRModule = toolchain.ReleaseGoModule

func bpfMLIRLine(ver string) string {
	return toolchain.ReleaseCompilerVersion + " (commit " + toolchain.ReleaseCompilerCommit[:8] + "; Go packages " + BpfMLIRModule + " " + ver + ", go.mod require"
}

func bmlLine() string { return toolchain.ReleaseBMLVersion + " (commit " + BML + ")" }
