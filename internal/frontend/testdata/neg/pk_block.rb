require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  ctx.check(0, 14) do |w|
    Out.update(0, w.u8(0))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:3
