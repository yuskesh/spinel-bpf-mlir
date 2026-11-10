require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  w = ctx.check(0, 14)
  unless w
    Out.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:3
