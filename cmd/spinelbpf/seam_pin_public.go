package main

import "github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"

// unverifiedBPFMLIRCommit is the driver's bpf-mlir commit when there is no ebpf-compile — in the public form, the commit
// of bpf-mlir's source release (the exported copy has no gitlink, or one that may point at the development pin).
func unverifiedBPFMLIRCommit(Config) (string, error) {
	return toolchain.ReleaseCompilerCommit, nil
}
