require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)


def prog(ctx)
  x = 0
  p = Out.lookup(0)
  if p
    x = p.load & 0xFF
  end
  Out.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 12:3
