require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)

# x = x * x three times on a u32 value — overflows the range taken in unrolled order (SB014)
def prog(ctx)
  x = 0
  p = Out.lookup(1)
  if p
    x = p.load & 0xFFFF_FFFF
  end
  3.times { x = x * x }
  Out.update(0, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 12:17
