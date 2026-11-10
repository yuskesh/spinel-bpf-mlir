package toolchain

const BPFMLIRGoModule = ReleaseGoModule

const (
	PinnedCompilerCommit = ReleaseCompilerCommit
	PinnedModuleVersion  = ReleaseGoModuleVersion
)

const (
	compilerFix = "build ebpf-compile from the bpf-mlir " + ReleaseCompilerVersion + " source release (commit " + ReleaseCompilerCommit + ") and point EBPF_COMPILE at it"
	moduleNote  = "the go-bpf-mlir release whose bpf-mlir Go packages are copied from commit " + ReleaseCompilerCommit
)

const submoduleWhat = "third_party/bpf-mlir/SOURCE_VERSION has source_commit"

func submoduleSource(repo string) (string, error) { return releaseSource(repo, ReleaseCompilerVersion) }
