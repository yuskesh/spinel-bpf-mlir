package main

import (
	"testing"

	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
)

func TestPublicSeamPin(t *testing.T) {
	if c, err := bpfMLIRCommit(Config{}, "0123"); err != nil || c != "0123" {
		t.Fatal(c, err)
	}
	if c, err := bpfMLIRCommit(Config{Repo: t.TempDir()}, ""); err != nil || c != toolchain.ReleaseCompilerCommit {
		t.Fatal(c, err)
	}
}
