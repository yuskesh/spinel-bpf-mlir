# USDT spec maps and the map declaration check

For a USDT program that uses `ebpf.usdt.arg`, bpf-mlir's compiler emits an array map
named `__ebpf_usdt_spec_<program>`. The map is not in the schema, but it is in the ELF
object and in the map rows of its requirements section. A maps.json built only from the
schema therefore fails the loader's two-way map check with `undeclared`. That rejection
follows bpf-mlir's requirements contract and must not be avoided by skipping the check.

To keep the two-way check, declare each spec map present in the ELF in maps.json:
name `__ebpf_usdt_spec_<program>`, kind `array`, key `u32`, value
`record:ebpf_usdt_spec`, max_entries the program's maximum number of points, flags 0.
The compiler rejects adding the reserved map to the schema directly. The internal
record is not in the schema's record table either, so a records check needs that
layout separately.

A contract that checks only some maps can set `allow_undeclared: true`, but this allows
**every** undeclared map, not only USDT spec maps. Excluding `__ebpf_*` maps from the
check by name is not done: a name is no evidence that the compiler created the map, and
an external ELF could escape the check that way.

## In this repository

The frontend has no USDT path, and the map declarations it derives from the schema do
not need to change. This page does not add USDT support and does not promise that an
external USDT ELF object loads. A future USDT path would need to generate the internal
map declarations from the schema's declarations and the compiler's internal layout,
not by copying them from the ELF.
