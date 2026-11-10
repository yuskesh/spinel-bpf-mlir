require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)
def et(w)
  w.u8(0)
end

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(2, 1)
  end
  Out.update(0, et(w) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 13:20
