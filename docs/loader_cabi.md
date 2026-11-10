# The loader's C ABI

The user-space library (`ruby/lib/spinelbpf.rb`) calls the C loader,
[bpf-mlir-loader](https://github.com/yuskesh/bpf-mlir-loader), through Spinel's FFI.
**The authoritative signatures are in bpf-mlir-loader's `shim/spinel/spinelbpf.h`**
(28 functions; the loader's own API is in `include/bml/*.h`). This page records the
conventions and where the library uses each function. If it disagrees with the header,
the header is right.

## Conventions

- **Result handles.** Every operation (load, close, attach, detach, the map, ring
  buffer and test-run functions, `object_unmet` and `possible_cpus`) returns an
  `int64_t` result handle. `spinelbpf_policy_version` and the result accessors below do
  not. The caller reads the result with the accessors: `spinelbpf_result_kind(r)`,
  `spinelbpf_result_value(r)` and `spinelbpf_result_unmet_count(r)` return `int64_t`,
  and `spinelbpf_result_message(r)` and `spinelbpf_result_unmet(r, i)` return C
  strings. The caller then **always frees it with `spinelbpf_result_free(r)`**
  (returns nothing; `SpinelBPF.check` frees on both success and error). The C strings
  belong to the result and become invalid after it is freed. A NUL inside a message is
  replaced by the two characters `\0`.
- **Kinds** (bpf-mlir-loader's `include/bml/kind.h`): 0 OK, 1 SCHEMA_MISMATCH,
  2 PRECHECK_FAILED, 3 TARGET_REJECTED, 4 VERIFIER_REJECTED, 5 OTHER, 6 STATE,
  7 RUNTIME_CONFLICT (reserved, never returned), 8 MAP_MISMATCH, 9 VALUE_RANGE,
  10 CONFIG_NOT_SET (reserved, never returned), 11 NOT_FOUND. The library raises one
  exception class per kind (`SpinelBPF::SchemaMismatch` ... `SpinelBPF::NotFound`).
- **Faults.** The loader installs no signal handler. A fault inside a call ends the
  process.
- **Handles.** Objects (the value of a load), links (the value of an attach) and ring
  buffer readers (the value of `ringbuf_open`) are `int64_t` numbers owned by the
  loader. Closing an object first closes its open readers. A process holds at most one
  object; a second load returns STATE. A second close, detach or `ringbuf_close` returns
  OK.
- **Map declarations.** Each map operation takes the map's declaration as one JSON
  object, of the same form as an element of the generated `maps.json`
  (`{"name":...,"kind":"array"|"hash"|...,"key":...,"value":...,"max_entries":n}`). The
  loader reads it strictly and checks it against the map rows of the ELF's requirements
  section; a mismatch returns MAP_MISMATCH.
- **Bytes.** Record values, hash keys and values, packets and ring buffer events are
  passed as `int64_t` arrays with one byte per element (Spinel's FFI `:int_array`).
  An element outside 0..255 returns VALUE_RANGE. Sizes are limited to 1..2^20 (for
  `hash_keys`, key size × capacity ≤ 2^26).
- **Embedded data.** `spinelbpf build` writes `<name>_embed.S`, which defines the data
  symbols `spinelbpf_elf_start` and `spinelbpf_elf_end` (the ELF object),
  `spinelbpf_schema_sha` (the schema's SHA-256 in hex), `spinelbpf_maps_json` (the
  maps.json text) and, only when the program has record maps, `spinelbpf_records` (the
  record layout table). The C code inside `ruby/lib/spinelbpf.rb` declares them as weak
  externs and reads them through its own functions `spinelbpf_embedded_elf`,
  `spinelbpf_embedded_elf_len`, `spinelbpf_embedded_sha`, `spinelbpf_embedded_maps` and
  `spinelbpf_embedded_records`. None of these are functions of the loader's C ABI.

## Functions

| Function | Arguments | Result value | Main kinds | Used by |
|---|---|---|---|---|
| `spinelbpf_load_checked` | ELF pointer and length, schema SHA, maps.json, caps source (0 = probe the running kernel) | object | SCHEMA_MISMATCH, PRECHECK_FAILED, TARGET_REJECTED, VERIFIER_REJECTED, MAP_MISMATCH, STATE | `SpinelBPF.load_embedded` |
| `spinelbpf_object_unmet` | object | unmet rows (`kind\tprogram\tname\tdetail`) | STATE | `Loaded#unmet` |
| `spinelbpf_close` | object | — | STATE | `Loaded#close` |
| `spinelbpf_attach_xdp` | object, program name, interface name | link | STATE, OTHER | `Loaded#attach_xdp` |
| `spinelbpf_detach` | link | — | STATE | `Link#detach` |
| `spinelbpf_map_get` | object, declaration, u32 key | the integer value | MAP_MISMATCH, VALUE_RANGE | `map_get` |
| `spinelbpf_map_put` | object, declaration, u32 key, value | 0 | MAP_MISMATCH, VALUE_RANGE | `map_put` |
| `spinelbpf_map_get_bytes` / `_put_bytes` | object, declaration, key, bytes, size | — (get writes the bytes) | MAP_MISMATCH | `map_get_record` / `map_put_record` |
| `spinelbpf_hash_get` | object, declaration, key bytes, value buffer | length | NOT_FOUND, MAP_MISMATCH | `hash_get*` / `hash_has*` |
| `spinelbpf_hash_put` | object, declaration, key bytes, value bytes | — | OTHER (`E2BIG — map is full`), VALUE_RANGE | `hash_put*` |
| `spinelbpf_hash_delete` | object, declaration, key bytes | 1 deleted, 0 absent | MAP_MISMATCH | `hash_delete*` |
| `spinelbpf_hash_keys` | object, declaration, key size, output, capacity | number of keys | OTHER (over capacity) | `hash_keys*` |
| `spinelbpf_possible_cpus` | — | number of possible CPUs | OTHER | `SpinelBPF.possible_cpus` |
| `spinelbpf_percpu_get` | object, declaration, key bytes, output, n | stride (value size rounded up to 8); the output holds CPUs × stride bytes | NOT_FOUND, MAP_MISMATCH | `percpu_get*` / `percpu_hash_*` |
| `spinelbpf_percpu_put` | object, declaration, key bytes, values, n | — (values are CPUs × value size, unpadded; the loader pads each CPU to 8 bytes) | MAP_MISMATCH, OTHER | `percpu_put*` |
| `spinelbpf_ringbuf_open` | object, ring buffer name | reader | STATE, MAP_MISMATCH | `Loaded#ringbuf` |
| `spinelbpf_ringbuf_read` | reader, timeout (ms), buffer, record size | bytes read (0 = timeout) | STATE, MAP_MISMATCH | `RingReader#read_record` |
| `spinelbpf_ringbuf_close` | reader | — | STATE | `RingReader#close` |
| `spinelbpf_test_run_xdp` | object, program, count (≥ 1) | XDP verdict | OTHER, VALUE_RANGE | `Loaded#test_run_xdp` (one run per count; EINTR is not retried) |
| `spinelbpf_test_run_xdp_packet` | object, program, packet bytes | XDP verdict | OTHER (data under 14 bytes), VALUE_RANGE | `Loaded#test_run_xdp_packet` |
| `spinelbpf_result_kind` / `_value` / `_message` / `_unmet_count` / `_unmet` / `_free` | result | — | STATE for an unknown handle | `SpinelBPF.check`, `Loaded#unmet` |
| `spinelbpf_policy_version` | — | the loader's policy version (not a result handle) | — | `SpinelBPF.policy_version` |

Attach and test-run functions for the other program kinds are small C wrappers inside
`ruby/lib/spinelbpf.rb` that call the loader's `bml_*` functions (declared in
bpf-mlir-loader's `include/bml/bml.h`) directly.

Messages from the shim start with `spinelbpf:`; messages from the loader start with
`bml:`.
