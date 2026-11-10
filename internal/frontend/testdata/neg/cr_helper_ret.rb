require "bpf"

Hits = BPF::Counter.new("Hits", :u64)
def cur
  Hits.value & 0xFFFF
end

def prog(ctx)
  v = cur
  Hits.add(v & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 10:3
