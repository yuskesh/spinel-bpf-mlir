require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)


def prog(ctx)
  w = ctx.check(14, 8)
  if w
    s = 0
    8.times { |i| s += w.u8(0) }
    Out.update(0, s)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 11:24
