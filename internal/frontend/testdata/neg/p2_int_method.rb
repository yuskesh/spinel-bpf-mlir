require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
U = BPF::ArrayMap.new("U", :u32, 4)

def prog(ctx)
  a = -7
  b = 3
  U.update(0, a.abs)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 9:15
