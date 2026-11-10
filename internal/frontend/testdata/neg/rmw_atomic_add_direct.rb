require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)


def prog(ctx)
  p = Out.lookup(0)
  if p
    Out.atomic_add(0, p.load & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 9:5
