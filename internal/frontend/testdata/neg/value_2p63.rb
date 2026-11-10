require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, 9223372036854775808)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 6:24
