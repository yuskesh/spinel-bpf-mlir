package frontend

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// The build-time uprobe check (a convenience for catching errors early: it does not replace the C loader (bml)'s check at load time;
// the target on the build machine and on the machine that runs the program are tied together by their sha256). It runs bpf-mlir's
// bindrt CheckTarget with "caps that answer only the uprobe questions" (caps: the capability answers CheckTarget asks for) and sorts
// the Unmet results (the unmet requirements) into three groups: the 14 kinds the build can read from the binary (7 for uprobe, 5 for
// the uretprobe return-value ABI and USDT, 2 for split DWARF) become SB032 at the declaration's position; the 58 kinds about kernel
// and loader capabilities are ignored (the build does not know the kernel); any kind in neither group stops the build with SB032
// (fail closed — when bpf-mlir adds a kind, the build stops until it is classified).

// UprobeBuildKinds is the set of uprobe Unmet kinds that stop the build (bpf-mlir requirements_format.md §6).
var UprobeBuildKinds = map[string]bool{
	"binary": true, "binary_unknown": true, "uprobe_symbol": true, "uprobearg": true, "uprobearg_unknown": true, "uprobearg_abi": true, "uprobearg_abi_unknown": true,
	// from bpf-mlir v1.10.0: kinds the build can read from the binary — the uretprobe return-value ABI and USDT points (spinel does not emit these yet)
	"uretprobe_abi": true, "uretprobe_abi_unknown": true, "usdt_probe": true, "usdtarg": true, "usdtarg_unknown": true,
	// from bpf-mlir v1.17.0: a split DWARF file whose build ID or debuglink CRC differs from the main binary's (readable from the file on the build machine)
	"uprobe_debug_build_id": true, "uprobe_debug_crc": true,
}

// UprobeBuildIgnored is the set of Unmet kinds the build ignores — questions about kernel capabilities (the build's caps answer
// "absent" for program types and map types, ErrUnknown for helpers, and do not answer any other optional question). At load time the
// C loader (bml) checks all of them against the real kernel.
var UprobeBuildIgnored = map[string]bool{
	// the 28 kinds of bpf-mlir e0a98646d — all questions about kernel or loader capabilities; spinel's ELFs do not have these rows yet:
	"arena_loader": true, "arena_loader_unknown": true, "attach_netkit_unknown": true, "coreenum": true, "coreenum_unknown": true, "datakptr_loader": true, "datakptr_loader_unknown": true,
	"enumval": true, "enumval_unknown": true, "fibflags": true, "fibflags_unknown": true, "funcret": true, "funcret_unknown": true, "helper_target": true, "helper_target_unknown": true,
	"kconfig": true, "kconfig_loader": true, "kconfig_loader_unknown": true, "kconfig_type": true, "kconfig_unknown": true, "kstructsize": true, "kstructsize_unknown": true,
	"ksymvar": true, "ksymvar_unknown": true, "sleepable_type": true, "sleepable_type_unknown": true, "typed_ksym_loader": true, "typed_ksym_loader_unknown": true,
	"program_type": true, "helper": true, "helper_unknown": true, "attach": true, "attach_tcx_unknown": true, "retsig_unknown": true,
	"farg": true, "farg_unknown": true, "attach_func_unknown": true, "arg_nullable_unknown": true, "arg_nullable": true, "arg_nullable_mark_unknown": true,
	"kfield": true, "attach_unknown": true, "kfield_unknown": true, "btf_feature": true, "btf_feature_unknown": true, "btf_rewrite": true,
	"arg_tag": true, "arg_tag_unknown": true, "map_type": true, "arch": true, "arch_unknown": true, "ctxfield": true, "ctxfield_unknown": true,
	"attach_symbol_unknown": true, "attach_alias": true, "attach_alias_unknown": true, "kprobearg": true, "kprobearg_unknown": true,
	"map_field": true, "map_field_unknown": true,
	// from bpf-mlir v1.10.0: questions about kernel capabilities (program-type attach, ctx fields, kfuncs, tracefs, replacement targets,
	// struct_ops) and about the loader's declarations
	"attach_target": true, "attach_target_unknown": true, "attach_type": true, "attach_type_unknown": true, "ctx_access": true, "ctx_access_unknown": true,
	"ext_target": true, "ext_target_unknown": true, "kfunc_allowed": true, "kfunc_allowed_unknown": true, "kfunc_sig": true, "kfunc_sig_unknown": true,
	"structop": true, "structop_unknown": true, "sysarg": true, "sysarg_unknown": true, "tpfield": true, "tpfield_unknown": true,
	"fsession_loader": true, "fsession_loader_unknown": true, "ksyscall_loader": true, "ksyscall_loader_unknown": true,
	"lsm_cgroup_loader": true, "lsm_cgroup_loader_unknown": true, "usdt_loader": true, "usdt_loader_unknown": true,
}

// uprobeBuildCaps is the build-time caps — it answers only for the uprobe binaries (the files at the declared paths).
type uprobeBuildCaps struct{ files map[string]string }

func (uprobeBuildCaps) HasProgType(string, int64) (bool, error) { return false, nil }
func (uprobeBuildCaps) HasHelper(string, int64, string, int64) (bool, error) {
	return false, requirements.ErrUnknown
}
func (uprobeBuildCaps) HasMapType(string, int64) (bool, error) { return false, nil }
func (c uprobeBuildCaps) UprobeBinary(program string) (io.ReaderAt, error) {
	p, ok := c.files[program]
	if !ok {
		return nil, fmt.Errorf("no target file for %s", program)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(b), nil
}

// debugRoot is the root of the build-time search for split DWARF by build ID (/usr/lib/debug, the same default as bml's load; ""
// means no search).
var debugRoot = "/usr/lib/debug"

// UprobeDebugFile returns the split DWARF of a target whose main binary has no DWARF (the system libc and the like) —
// root/.build-id/xx/rest.debug.
func (uprobeBuildCaps) UprobeDebugFile(_ string, buildID []byte) (io.ReaderAt, error) {
	root := debugRoot
	if mutation("uprobe-debug-off") { // mutation: do not search for split DWARF — libc's argument and return types become Unknown
		root = ""
	}
	p, err := requirements.BuildIDDebugPath(root, buildID)
	if err != nil {
		return nil, err
	}
	return requirements.ReadUprobeDebugFile(p)
}

// UprobeBuildCheck checks the ELF's uprobe requirements against the target files at build time (it does nothing when there is no
// uprobe program).
func UprobeBuildCheck(elf []byte, res *Result) error {
	files := map[string]string{}
	decl := map[string]Pos{}
	for _, p := range res.Programs {
		if p.Kind == "uprobe" || p.Kind == "uretprobe" { // uretprobe is checked against the target file too (uretprobe_abi)
			files[p.Name], decl[p.Name] = p.BinaryPath, p.DeclPos
		}
	}
	return UprobeBuildCheckFiles(elf, files, decl)
}

// UprobeBuildCheckFiles is the body of UprobeBuildCheck's check — it takes maps from program name to target file and to declaration
// position (the seam passes them from the consumer's uprobe_targets).
func UprobeBuildCheckFiles(elf []byte, files map[string]string, decl map[string]Pos) error {
	if len(files) == 0 {
		return nil
	}
	parsed, err := bindrt.Parse(elf)
	if err != nil {
		return fmt.Errorf("the build-time uprobe check could not read the ELF: %w", err)
	}
	us, err := parsed.CheckTarget(uprobeBuildCaps{files})
	if err != nil {
		return fmt.Errorf("the build-time uprobe check failed: %w", err)
	}
	// one SB032 per program (one cause — a missing symbol, say — yields uprobe_symbol plus a uprobearg_unknown per argument, so the
	// lines are joined into one message)
	lines := map[string][]string{}
	var order []string
	for _, u := range us {
		if UprobeBuildIgnored[u.Kind] {
			continue
		}
		if _, seen := lines[u.Program]; !seen {
			order = append(order, u.Program)
		}
		if UprobeBuildKinds[u.Kind] {
			lines[u.Program] = append(lines[u.Program], fmt.Sprintf("%s %s: %s", u.Kind, u.Name, u.Detail))
			continue
		}
		lines[u.Program] = append(lines[u.Program], fmt.Sprintf("%s %s: %s (an Unmet kind the build-time check does not classify — stopping, fail closed; classify it in UprobeBuildKinds or UprobeBuildIgnored)", u.Kind, u.Name, u.Detail))
	}
	var ds Diags
	for _, p := range order {
		ds = append(ds, Diag{Verdict: Rejected, Code: SB032UprobeTarget, Pos: decl[p],
			Msg: fmt.Sprintf("the uprobe target fails bpf-mlir's check before load: %s (the build checks the file it read; the load checks the running target again)", strings.Join(lines[p], "; "))})
	}
	if len(ds) > 0 {
		return &Error{Diags: ds}
	}
	return nil
}
