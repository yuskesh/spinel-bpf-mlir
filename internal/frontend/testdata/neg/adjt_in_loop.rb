require "bpf"


Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(ctx)
  2.times do |i|
    st = ctx.adjust_tail(-4)
    Out.update(0, st)
  end
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 8:5
