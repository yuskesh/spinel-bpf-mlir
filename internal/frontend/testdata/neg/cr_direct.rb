require "bpf"

Hits = BPF::Counter.new("Hits", :u64)
def prog(ctx)
  Hits.add(Hits.value & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 5:3
