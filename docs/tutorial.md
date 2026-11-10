# Tutorial

This page builds spinel-bpf-mlir v0.9.0, checks the versions, and runs four example
programs (XDP, tcx, uprobe and tp_btf) in the kernel with `--selftest`.

Read the limits in [release.md](release.md) first. Kernel execution has been verified on
Linux 7.1.8 (x86_64) only.

## Step 0: build and check the versions

Requirements: Linux x86_64, LLVM / MLIR 23.1.1 (`/opt/llvm-23.1.1`), Go 1.27, gcc,
make, CMake, Ninja, git, network access, and root (`sudo`) for steps 1 to 4.

```sh
git clone --recurse-submodules --branch v0.9.0 https://github.com/yuskesh/spinel-bpf-mlir
cd spinel-bpf-mlir
scripts/setup.sh
go build -o build/bin/spinelbpf ./cmd/spinelbpf
build/bin/spinelbpf --version
```

The first line of `--version` is `spinel-bpf-mlir v0.9.0 (commit <12 hex digits>)`.
A `+dirty` suffix means the working tree has changes. The following lines name the
pinned dependencies:

```
bpf-mlir v1.21.0 (commit 41b18856; Go packages github.com/yuskesh/go-bpf-mlir v0.19.0, go.mod require)
bml <commit>
spinel 086d514d
ebpf-compile: <the --version line of the ebpf-compile that setup built>
```

`ebpf-compile: not found` means `scripts/setup.sh` has not finished.

## Step 1: XDP, counting packets (xdpcount)

In `examples/xdpcount/xdpcount.rb`, `count_pkts` is the eBPF side (`BPF.xdp`) and the
rest of the file is the user-space side (`SpinelBPF.load_embedded`).

```sh
build/bin/spinelbpf build -o build/bin/xdpcount examples/xdpcount/xdpcount.rb
sudo build/bin/xdpcount --selftest 10
```

The build writes the `.mlir`, schema, maps.json and ELF into `examples/xdpcount/`.
They are byte-identical to the committed files, so `git status` stays clean.
`--selftest` does not attach. It runs the program ten times with BPF_PROG_TEST_RUN
and checks the count.

## Step 2: tcx ingress and egress (tccount)

```sh
build/bin/spinelbpf build -o build/bin/tccount examples/tccount/tccount.rb
sudo build/bin/tccount --selftest
```

## Step 3: uprobe, the arguments of a C function (greetwatch)

The build writes the SHA-256 of the uprobe target (`examples/greetwatch/target/greeter`)
into the schema, so a different target binary is rejected at load.

```sh
build/bin/spinelbpf build -o build/bin/greetwatch examples/greetwatch/greetwatch.rb
sudo build/bin/greetwatch --selftest --target examples/greetwatch/target/greeter
```

## Step 4: tp_btf and CO-RE, fields of a kernel struct (forkcount)

`BPF.kernel_type` declares the `task_struct` fields the program reads. The loader
checks their width, sign and name against the kernel's BTF before loading.

```sh
build/bin/spinelbpf build -o build/bin/forkcount examples/forkcount/forkcount.rb
sudo build/bin/forkcount --selftest
```

## Next

- Write your own program: see the README and the programs under `examples/`.
  Ruby outside the subset stops the build with a position and a reason code (the
  table is in [release.md](release.md)).
