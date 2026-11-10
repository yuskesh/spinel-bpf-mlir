require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 99999999999999999999)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog

def count(x)
  x + 1
end
puts count(1)
# want: SB014 3:44
