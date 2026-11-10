require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Small = BPF::ArrayMap.new("Small", :u32, 1073741823) # the bpf-mlir v0.17.0 limit (the kernel rejects the BTF of a larger map; the C loader stops with btf_dropped)

def prog(ctx)
  Small.atomic_add(1073741822, 4294967295) # the key is the map range's upper edge, the value the largest u32
  Counts.atomic_add(1, 9223372036854775807)
  Small.update(0, 4294967295)
  p = Small.lookup(3)
  if p
    Small.update(1, p.load)
  else
    Counts.atomic_add(1, 0)
  end
  return BPF::XDP_DROP
end
BPF.xdp :prog
