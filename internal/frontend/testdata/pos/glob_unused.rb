require "bpf"

# An unused global (declared only): an SB013 Conditional; it does not appear in the ELF, schema, maps.json or table
Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Unused = BPF::Counter.new("Unused", :u64)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
