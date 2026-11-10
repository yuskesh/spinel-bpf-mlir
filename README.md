# spinel-bpf-mlir

Write the user-space side and the eBPF side of a program in one Ruby source file and
build them into one executable.

- The **eBPF side** is a restricted subset of Ruby. The frontend in this repository reads
  [Spinel](https://github.com/matz/spinel)'s AST and inferred types, emits the `ebpf`
  MLIR dialect of [bpf-mlir](https://github.com/yuskesh/bpf-mlir) and a schema, and
  bpf-mlir's `ebpf-compile` turns them into a BPF ELF object with BTF.
- The **user-space side** is ordinary Ruby compiled by Spinel (an ahead-of-time Ruby
  compiler: Ruby to C to a native executable). The ELF object is embedded in the
  executable. The `SpinelBPF` library loads it through
  [bpf-mlir-loader](https://github.com/yuskesh/bpf-mlir-loader), which checks the
  object's requirements, schema hash and map declarations against the running kernel
  before the program is loaded.
- Maps, ring buffers and record types are declared once in the Ruby source and shared
  by both sides.

Ruby outside the subset is rejected with a position and a reason code; nothing is
silently approximated. Release notes, limits and the reason code table are in
[docs/release.md](docs/release.md). Start with [docs/tutorial.md](docs/tutorial.md).

## Requirements

- Linux x86_64. Kernel execution has been verified on Linux 7.1.8 only.
- LLVM / MLIR 23.1.1 (default prefix `/opt/llvm-23.1.1`, override with `LLVM_PREFIX`)
- Go 1.27 (the frontend and the build driver are written in Go)
- gcc, make, CMake, Ninja, git, and network access for the submodules and Spinel's
  libprism
- root, or the capabilities listed below, to load programs

## Build

```sh
git clone --recurse-submodules https://github.com/yuskesh/spinel-bpf-mlir
cd spinel-bpf-mlir
scripts/setup.sh
go build -o build/bin/spinelbpf ./cmd/spinelbpf
build/bin/spinelbpf --version
```

`scripts/setup.sh` builds bpf-mlir's `ebpf-compile`, the C loader archives and Spinel.

`spinelbpf build [-o exe] x.rb` writes the generated `.mlir`, `.schema.json`,
`.maps.json`, `.domain.json`, `.bpf.o` and `_embed.S` / `_embed.o` next to `x.rb`, and
with `-o` links one executable. The same source always produces byte-identical
generated files. `--emit=domain-graph` writes only the domain graph (the program roots,
which functions belong to the user side and the eBPF side, and the verdicts).

## Program kinds

| Declaration | Kind |
|---|---|
| `BPF.xdp :name` | XDP |
| `BPF.tcx :name, :ingress` / `:egress` | sched_cls on tcx |
| `BPF.socket_filter :name` | socket filter (`skb.len` only) |
| `BPF.cgroup_skb :name, :ingress` / `:egress` | cgroup skb |
| `BPF.netfilter :name` | netfilter hook |
| `BPF.flow_dissector :name` | flow dissector |
| `BPF.fentry` / `BPF.fexit` / `BPF.fmod_ret` | tracing (BTF) |
| `BPF.kprobe` / `BPF.kretprobe` / `BPF.ksyscall` | kprobe |
| `BPF.uprobe` / `BPF.uretprobe` | uprobe on a C function of a binary |
| `BPF.tracepoint` / `BPF.raw_tp` / `BPF.tp_btf` | tracepoints |

Each kind's program is a top-level `def` whose argument is the context. Verdicts are
named constants (`BPF::XDP_PASS`, `BPF::TC_DROP`, `BPF::SF_KEEP`, `BPF::CG_ALLOW`,
`BPF::NF_ACCEPT`, `BPF::FLOW_OK`, ...), and mixing constants of another kind is
rejected.

## Maps and events

- Arrays and hashes of integers or records: `BPF::ArrayMap`, `BPF::HashMap`,
  `BPF::LruHashMap`, the `Record` variants, per-CPU variants, and `BPF::LpmTrieMap`
  (IPv4 longest-prefix match).
- Records are Ruby `Struct`s with a layout declared by
  `BPF.record(S, a: :u8, _pad0: :u8, b: :u16)`. Array members are declared as
  `hist: [:u32, 8]`.
- Ring buffers of records: `R = BPF::RingBuf.new("R", S.new(0, ...), size)` and
  `if R.output(S.new(...))`. Dropping the result of an output or the status of a hash
  operation is rejected; write `_ = ...` to drop it on purpose.
- Globals: `BPF::Config`, `BPF::OptionalConfig`, `BPF::Counter`.

On the eBPF side, a lookup is read inside its own check: `p = M.lookup(k)` and then
`p.load` or `p.atomic_add(d)` inside `if p`. Packet bytes are read the same way:
`w = ctx.check(off, len)` and then `w.u8(i)` or `w.be16(i)` inside `if w`.

On the user-space side, the `SpinelBPF` library loads the embedded object and reads
and writes maps: `SpinelBPF.load_embedded`, `map_get` / `map_get_record`,
`hash_get` / `hash_put` / `hash_keys`, `percpu_get`, `ringbuf(R).read_record(ms)`,
`attach_*` and `test_run_*`. The API is monomorphic: integer and record maps use
different methods, because a value whose type depends on the map would break Spinel's
whole-program type inference of the eBPF side.

## The eBPF subset

- Integer locals, arithmetic and comparisons. Each integer has an interval, and
  operations whose Ruby meaning and BPF meaning could differ are rejected: a result
  outside 64 bits (Ruby would promote to a Bignum), out-of-range literals, and indices
  that cannot be shown in range.
- `/` and `%` keep Ruby's floor semantics. The divisor must be a nonzero constant; a
  dividend that may be negative needs a divisor of ±2^k.
- Bounded loops: `N.times`, `(0...k).each` with a known bound.
- Conditions narrow the interval of a local inside the branch
  (`if k >= 0 && k < 8` allows `p.load.hist[k]`).
- Early returns at the top of a program: `return BPF::XDP_DROP if cond`. All guards of
  one program return the same verdict.
- Helpers: `BPF.pid_tgid`, `BPF.ktime_ns` and others.
- Top-level `def`s called from a program become BPF subprograms, with up to five
  integer arguments, or one map value, packet window or packet context. Recursion is
  rejected. A helper's return value is a full 64-bit integer at the call site.
- A read-modify-write of a shared map entry without an atomic operation is rejected,
  across helper calls as well. Per-CPU maps used only by XDP programs are exempt.
- Kernel structs (CO-RE): `BPF.kernel_type(Task, "task_struct", pid: :i32)` declares
  the fields a program reads. Fields that may be NULL are read only inside `if`.
  **The width, sign, name and length of a declared field are checked only by the
  loader at load time against the kernel's BTF**; a wrong declaration builds and is
  then rejected at load.
- uprobe targets are paths relative to the source directory, or clean absolute paths.
  Their SHA-256 is written into the schema, and the build checks the declared
  arguments against the binary's symbols and DWARF.

The full rules, with examples, are the positive and negative inputs under
`internal/frontend/testdata/` and the programs under `examples/`.

## Non-root loading

Measured on Linux 7.1.8: XDP and sched_cls need CAP_BPF and CAP_NET_ADMIN (XDP with a
variable packet offset also needs CAP_PERFMON), tp_btf needs CAP_BPF and CAP_PERFMON,
and uprobe needs CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN. Other kinds have not been
measured without root.

## Known limits

- The user-space side cannot hold the i64 value −2^63, because Spinel uses it to mark
  `nil`. The library raises `SpinelBPF::ValueRange` instead of returning `nil`. The
  eBPF side handles the value normally.
- With more than one record type in a program, assigning to an index of a `dup`ed
  record (`r[i] = v`) does nothing in Spinel. Use the member setter or `S.new(...)`.
- A user program that requires `spinelbpf` cannot define a top-level constant with
  the same name as a class nested in the library (`State`, `Other`, `Link`, `Error`):
  Spinel gives both the same C name and the C compile fails.
- Spinel's `Thread` can be used on the user-space side. Load only on the main thread,
  read and close a ring buffer reader only on the thread that opened it, and join other
  threads before closing the object.

## License

See `LICENSE` and `NOTICE`.
