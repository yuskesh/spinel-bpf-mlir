require "bpf"
M = BPF::ArrayMap.new("M", :u64, 4)

def get(k)
  r = 0
  q = M.lookup(k & 3)
  if q
    r = q.load & 0xFF
  end
  r
end
def prog(ctx)
  v = get(0)
  M.update(0, (v & 0xFF) + 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 14:3
