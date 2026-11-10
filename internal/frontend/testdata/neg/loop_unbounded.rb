require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)


def prog(ctx)
  k = 0
  w = ctx.check(0, 1)
  if w
    k = w.u8(0)
  end
  s = 0
  k.times { |i| s += i }
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 13:3
