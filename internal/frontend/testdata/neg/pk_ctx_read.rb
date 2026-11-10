require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  x = ctx.u8(0)
  Out.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 6:7
