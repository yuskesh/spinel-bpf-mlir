require "bpf"

# The adjust_tail delta is not a literal (a local)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(ctx)
  d = -4
  st = ctx.adjust_tail(d)
  Out.update(0, st)
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB014 8:24
