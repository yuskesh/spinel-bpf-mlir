require "bpf"


def p(ctx)
  w = ctx.check(14, 20)
  if w
    w.set_u8(0, 1)
  end
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB002 7:5
