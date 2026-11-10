require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
U = BPF::ArrayMap.new("U", :u32, 4)

def prog(ctx)
  a = -7
  b = 3
  if a < 1
    y = 1
  end
  U.update(0, y)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB001 12:15
