require "bpf"


def p(ctx)
  w = ctx.check(0, 14)
  if w
    w.set_u8(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 7:5
