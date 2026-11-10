package main

import "github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"

func unverifiedBPFMLIRCommit(Config) (string, error) {
	return toolchain.ReleaseCompilerCommit, nil
}
