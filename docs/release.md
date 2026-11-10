# Release notes

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
- `spinelbpf --version` prints `spinel-bpf-mlir v0.9.1 (commit <build commit>[+dirty])`.
  The version is written only into the second line of each generated `.mlir`
  (`// spinel-bpf-mlir v0.9.1`). Schemas, maps.json, domain.json and ELF objects carry
  no version.

### Dependencies

| Dependency | Version |
|---|---|
| bpf-mlir (`ebpf-compile`) | v1.21.0 |
| go-bpf-mlir (Go packages) | v0.19.0 |
| bpf-mlir-loader | v0.1.0 |
| Spinel | commit 086d514d |
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
