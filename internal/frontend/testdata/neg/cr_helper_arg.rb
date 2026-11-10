require "bpf"

Hits = BPF::Counter.new("Hits", :u64)
def bump(d)
  Hits.add(d & 0xFF)
  0
end

def prog(ctx)
  bump(Hits.value & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 10:3
