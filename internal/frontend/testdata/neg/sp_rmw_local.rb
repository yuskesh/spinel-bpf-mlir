require "bpf"
M = BPF::ArrayMap.new("M", :u64, 4)

def put(v)
  M.update(1, v & 0xFFFF)
  0
end
def prog(ctx)
  x = 0
  p = M.lookup(0)
  if p
    x = p.load & 0xFF
  end
  put(x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 14:3
