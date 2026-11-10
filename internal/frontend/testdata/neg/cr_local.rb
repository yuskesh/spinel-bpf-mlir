require "bpf"

Hits = BPF::Counter.new("Hits", :u64)
def prog(ctx)
  v = Hits.value & 0xFF
  Hits.add(v)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 6:3
