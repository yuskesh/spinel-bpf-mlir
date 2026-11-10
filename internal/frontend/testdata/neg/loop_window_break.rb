require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)


def prog(ctx)
  off = 14
  8.times do |i|
    w = ctx.check(off, 2)
    if w
      break if w.u8(0) == 0
      off += 2
    end
  end
  Out.update(0, off)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 12:7
