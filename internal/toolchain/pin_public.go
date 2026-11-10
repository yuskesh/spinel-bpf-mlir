package toolchain

// BPFMLIRGoModule is the path of the Go module to check — in the public form, go-bpf-mlir, which copies bpf-mlir's Go
// packages.
const BPFMLIRGoModule = ReleaseGoModule

// PinnedCompilerCommit is the commit of bpf-mlir's source release; PinnedModuleVersion is the go-bpf-mlir release that
// copies the packages from that commit.
const (
	PinnedCompilerCommit = ReleaseCompilerCommit
	PinnedModuleVersion  = ReleaseGoModuleVersion
)

// compilerFix is the remedy named by a compiler-check error; moduleNote is the note on a module-version error.
const (
	compilerFix = "build ebpf-compile from the bpf-mlir " + ReleaseCompilerVersion + " source release (commit " + ReleaseCompilerCommit + ") and point EBPF_COMPILE at it"
	moduleNote  = "the go-bpf-mlir release whose bpf-mlir Go packages are copied from commit " + ReleaseCompilerCommit
)

// submoduleWhat is the subject of check 4's error message (where the submodule's commit comes from).
const submoduleWhat = "third_party/bpf-mlir/SOURCE_VERSION has source_commit"

// submoduleSource is check 4's value: in the public form, the source_commit in third_party/bpf-mlir/SOURCE_VERSION (the
// HEAD of the public bpf-mlir submodule is the export commit, a different SHA from ReleaseCompilerCommit).
func submoduleSource(repo string) (string, error) { return releaseSource(repo, ReleaseCompilerVersion) }
