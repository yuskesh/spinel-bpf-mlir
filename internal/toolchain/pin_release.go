package toolchain

// ReleaseCompilerVersion and ReleaseCompilerCommit are the bpf-mlir source release that the public form (the public
// build) builds with; ReleaseGoModule and ReleaseGoModuleVersion are the public go-bpf-mlir release that copies
// that commit's bpf-mlir Go packages (bindrt, layout, requirements).
// Earlier: go-bpf-mlir v0.19.0 (the copy of the Go packages of bpf-mlir commit C = 41b188568; before it, v0.18.0 = the copy
// of d3e13842). Before publication it could not be fetched from the Go proxy, so the build that really fetched the module
// at that version was the isolated acceptance build after publication (a fresh build of the public bpf-mlir group).
// Now (the public bpf-mlir release at 2bf112303, with a matching go-bpf-mlir release): bpf-mlir v1.22.0 (source
// 2bf112303, the dev pin), go-bpf-mlir v0.20.0 (its Go packages), bml v0.1.1
// (SOURCE_VERSION source_commit ad2eafd; the public repository commit is ffd32ad7).
// It sits in a file without a build tag (the development form's TestReleasePinSameCompilerSource checks it against the
// development pin).
const (
	ReleaseCompilerVersion = "v1.22.0"
	ReleaseCompilerCommit  = "2bf112303e42e1a176fc8b248948277ef3dfffc0"
	ReleaseGoModule        = "github.com/yuskesh/go-bpf-mlir"
	ReleaseGoModuleVersion = "v0.20.0"
	// The public bpf-mlir-loader version and the source_commit in its SOURCE_VERSION (not the public repository's commit
	// 42210a00 — checked against the public repository)
	ReleaseBMLVersion      = "v0.1.1"
	ReleaseBMLSourceCommit = "ad2eafdc77e610ced3d83d2b39dd3c7ae81b88bc"
)
