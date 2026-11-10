require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  e = ctx.check(0, 14)
  if e
    w = ctx.check(e.u8(0) - 20, 4)
    if w
      Out.update(0, w.u8(0))
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB023 8:19
