require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
U = BPF::ArrayMap.new("U", :u32, 4)

def prog(ctx)
  a = -7
  b = 3
  if a && b
    U.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 9:6
