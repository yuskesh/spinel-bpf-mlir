# Release notes

## v0.11.0

- **Added, struct_ops:** `BPF.struct_ops` declares a table of kernel callbacks filled with
  eBPF programs, for `tcp_congestion_ops` and `sched_ext_ops`.
  - In a `tcp_congestion_ops` member, the socket argument is read only as
    `tp = ctx.kptr_or_null(i, T)`, with `T` a `tcp_sock` kernel type, followed by `if tp`.
    An integer field of it is written with `tp.set_field(:m, v)`, and only when `v` fits
    the field.
  - In `sched_ext_ops`: the `BPF::Scx` ops and constants, `BPF::Global` (a `.bss` value
    with `value` and `set`) and `BPF::ExitInfo` (the exit record).
  - On the user side, `SpinelBPF` registers a table and returns its link, which detaches
    and closes it.
  - Four new examples: `tcp_cc_count`, `tcp_cc_reno`, `scx_basic` and `scx_simple`.
  - Measured in a VM on Linux 7.3.1 only.
- **Added, u64 values:** a local that holds a u64 value (from `ctx.read(…, :u64)`, a u64
  map value or an intrinsic) is accepted. It may be copied, joined with another u64 value,
  masked, shifted right, stored into a u64 slot or passed to a u64 operand. v0.10.0 refused
  the copy to a local with SB014. Its other uses still stop with SB014, SB001 or SB005. New
  intrinsics: `BPF.u64_add`, `BPF.u64_sub` and `BPF.u64_mul` (modular), `BPF.u64_div` (the
  divisor in 1..2^63 − 1) and `BPF.time_before`.
- **Changed, refused programs:** a `return` in a program of a kind with no verdict
  (fentry, fexit, kprobe, kretprobe, uprobe, uretprobe, tp_btf, raw_tp, tracepoint and
  ksyscall) now stops with SB008 at the `return`. v0.10.0 dropped it silently, so an early
  `return if c` did not return. To keep such a program, use `if`/`else` instead.
- **Changed, Spinel:** the pinned Spinel is commit 0d58c397. It fixes wrong line numbers in
  a file where a comment holds the word `break`. One refusal changes its code: reading an
  undeclared field through an embedded kernel struct (`sk.load.__sk_common.skc_nope`) stops
  with SB033 instead of SB004, at the same position.
- **Changed, dependencies:** bpf-mlir v1.23.0, go-bpf-mlir v0.21.0 and bpf-mlir-loader
  v0.2.0 (from v1.22.0, v0.20.0 and v0.1.1).

## v0.10.0

- **Changed, accepted programs:** a value read by `v, st = ctx.read(n, off, :u64)` is now
  handled like a u64 map value. It may be masked with a non-negative literal on the left
  (`v & M`), shifted right by a literal 1..63 (`v >> K`, now a logical shift), or copied
  straight into a u64 map value or u64 record member (newly accepted). Every other use is
  refused with SB014: comparisons, copies to a local, reassignment and `v op= …`, `+ - * / %`,
  `| ^`, `>> 0`, a mask on the right or a negative mask, and a store to a non-u64
  destination. A name that is such a value on one path and an Integer on another is
  refused when read. v0.9.1 accepted some of these and lowered `>>` and comparisons as
  signed operations, which is wrong for a value of 2^63 or more. To keep a program
  accepted, narrow the value first: `y = v & 0xFFFF_FFFF` or `y = v >> 32`.
- **Changed, the build:** `spinelbpf` is now a C program, built with
  `scripts/build-c-driver.sh build/bin`. Building needs no Go; Go 1.27 is needed only to
  run the tests. The generated files are byte-identical to those of the Go build, and
  `--version` prints the same lines as the Go build would.
- **Fixed:** an index literal outside the supported range in `kptr(i, T)`,
  `kptr_or_null(i, T)` or the tracing `arg(i)` now stops with SB014 at the literal, instead
  of crashing the frontend. No accepted program changes.
- **Changed, dependencies:** bpf-mlir v1.22.0, go-bpf-mlir v0.20.0 and bpf-mlir-loader
  v0.1.1 (from v1.21.0, v0.19.0 and v0.1.0).

## v0.9.1 — go.sum fix

- **Fixed:** the `go.sum` of v0.9.0 recorded a stale checksum for
  `github.com/yuskesh/go-bpf-mlir v0.19.0`, so `go mod download` in a fresh clone of
  v0.9.0 failed with a checksum mismatch. v0.9.1 records the correct checksum.
- **Unchanged:** everything else. The accepted and rejected programs, the reason codes,
  the dependencies and the generated ELF objects are the same as in v0.9.0. Only the
  version string changes, in `--version` and in the second line of each generated
  `.mlir`.
- The tutorial's `--version` output now shows the bml line as the build prints it
  (`bml v0.1.0 (commit 41ec56f)`).
- The limits, the version promise and the dependencies below apply to v0.9.1 as well.

## v0.9.0 — first public release

### Limits (read first)

- **Linux x86_64 only. Kernel execution was verified on Linux 7.1.8 only.** Other
  kernel versions have not been run.
- **Non-root loading was measured only for some kinds** (see the README). fentry,
  fexit and kprobe without root, and NULL-able kernel pointers, array field copies and
  fentry struct arguments without root, have not been measured.
- **Some declarations are trusted and not checked**: the width and sign of `ret:` for
  kretprobe and uretprobe, and the offset of `ctx.read` in a kprobe. A wrong declaration
  reads a wrong value without an error. Kernel struct fields (`BPF.kernel_type`),
  tracepoint `fields:`, ksyscall `params:` and fentry `args:` are checked by the loader
  against the kernel before load, not by the build.
- **The native model is Spinel, not CRuby.** The tests compare the kernel against the
  same Ruby source compiled natively by Spinel. Where Spinel's meaning differs from
  CRuby's, the tests do not see it.
- **Network programs were measured with test runs and the process's own resources only**
  (its own network namespace's loopback, its own sockets, a child cgroup). Delivery to
  a redirect target, the real effect of sk_lookup and flow_dissector, native XDP
  headroom on real drivers, IPv6 and most of TCP were not measured.
- **Programs attached system-wide** (tracepoint, ksyscall, kprobe, raw_tp, kretprobe)
  were tested by counting the test process's own events only.
- **User strings** read by tracepoints, ksyscall arguments and argv come back empty
  (−EFAULT) when their page has not been faulted in; BPF cannot fault a page in. argv
  is cut at the first 20 elements, and an event cannot tell exactly 20 from more.
- **Large ring buffer events** (over about 109 KB, which the compiler outlines) are
  accepted and compiled, but their contents were not checked in the kernel. Building
  such a record with Spinel takes more than 30 minutes.
- **Many negative inputs stop with SB001**: Spinel gives no type to the construct, and
  the frontend stops at that position without a more specific message.
- **lpm_trie** is IPv4 with 32-bit values only. **adjust_tail** takes only a literal
  delta of 0 or less. **socket_filter** can only keep or drop the whole packet.
- **The i64 value −2^63 cannot be held on the user-space side** (Spinel uses it to mark
  `nil`); the library raises `SpinelBPF::ValueRange`.
- **Cross-function read-modify-write checks do not distinguish map keys**, so they may
  reject a program whose caller and helper touch different keys. Move the write to the
  caller, or use different maps.

### Version promise

- v0.x makes **no compatibility promise**. The CLI, the public Ruby names (the `BPF` DSL
  and the `SpinelBPF` library), the reason codes and the generated file formats can
  change in the next release. Changes are named in that release's notes.
- Reason codes are never renumbered or reused. New codes are appended. SB012 is retired.
- `spinelbpf --version` prints `spinel-bpf-mlir v0.11.0 (commit <build commit>[+dirty])`.
  The version is written only into the second line of each generated `.mlir`
  (`// spinel-bpf-mlir v0.11.0`). Schemas, maps.json, domain.json and ELF objects carry
  no version.

### Dependencies

| Dependency | Version |
|---|---|
| bpf-mlir (`ebpf-compile`) | v1.23.0 |
| go-bpf-mlir (Go packages) | v0.21.0 |
| bpf-mlir-loader | v0.2.0 |
| Spinel | commit 0d58c397 |
| LLVM / MLIR | 23.1.1 |
| Go | 1.27 |

### Reason codes

A rejected program reports a verdict, a reason code, a position and, where it applies,
a call path.

| code | name | meaning |
|---|---|---|
| SB000 | Spinel | Spinel rejected the program, or its output could not be read |
| SB001 | UnsupportedConstruct | a syntax, type or value outside the subset |
| SB002 | UnsupportedCall | a call or call target outside the subset |
| SB003 | CrossDomainUse | a function used by both the user side and the eBPF side, or an API used on the wrong side |
| SB004 | UnknownEdge | a call edge that cannot be followed statically |
| SB005 | RefCheckShape | a use outside the `if` that checks a lookup, packet window, string output or kernel pointer |
| SB006 | NonConstant | a non-constant where a constant is required |
| SB007 | ReservedName | a name with a reserved prefix (`spinelbpf_`, `_spinelbpf_`, `__ebpf_`) |
| SB008 | ProgramShape | the shape of a program declaration and its `def` |
| SB009 | OperatorRedefined | a redefined built-in operator |
| SB010 | TypingProbe | the type check of a program root failed |
| SB011 | ShadowedName | a reopened DSL name, or a call target missing from the DSL |
| SB012 | ThreadInUserSide | retired (the user side may use `Thread`); the number is not reused |
| SB013 | MapDeclShape | the shape of a map declaration |
| SB014 | SemanticGap | Ruby and BPF would give different results (overflow, division, literal range, ...) |
| SB015 | AmbiguousType | a node with more than one type |
| SB016 | DynamicProgram | `method_missing`, `define_method`, `send`, `eval` and similar |
| SB017 | InternalEmitter | an internal error of the frontend |
| SB018 | LogicalSideEffect | a side effect in the right operand of `&&` or `\|\|` |
| SB019 | SharedReadModifyWrite | a non-atomic read-modify-write of a shared map entry |
| SB020 | KeyOutOfRange | a map key whose interval is outside [0, max_entries − 1] |
| SB021 | CompileWarning | a warning from `ebpf-compile` (does not stop the build) |
| SB022 | WindowIndex | a packet window length, or a read index outside the window |
| SB023 | PacketOffset | a packet window offset whose interval is out of range |
| SB024 | RecordShape | the shape of a record declaration or construction |
| SB025 | DroppedEvent | the result of a ring buffer output is dropped |
| SB026 | StatusIgnored | the status of a map or helper operation is dropped |
| SB027 | ThreadInBPFSide | `Thread` and similar inside a function the eBPF side reaches |
| SB028 | TracingKind | an operation or constant of another program kind |
| SB029 | GlobalShape | the declaration or use of a global |
| SB030 | LoopShape | a loop that is not of a bounded form |
| SB031 | IndexRange | an index into a record array member that cannot be shown in range |
| SB032 | UprobeTarget | the build-time check of a uprobe target failed |
| SB033 | KernelTypeShape | the declaration or use of a kernel struct, kernel pointer or its arguments |
| SB034 | SubprogramShape | the shape of an eBPF-side `def`: arguments, return value and allowed operations |
| SB035 | Recursion | a cycle in the call graph of eBPF-side `def`s (with the path) |
