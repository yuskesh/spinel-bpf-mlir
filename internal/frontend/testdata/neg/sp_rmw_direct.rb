require "bpf"
M = BPF::ArrayMap.new("M", :u64, 4)

def put(v)
  M.update(1, v & 0xFFFF)
  0
end
def prog(ctx)
  p = M.lookup(0)
  if p
    put(p.load & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 11:5
