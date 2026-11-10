require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)

# The offset grows by a be16 each iteration — exceeds [0, 65533] in the range taken in unrolled order (SB023)
def prog(ctx)
  off = 14
  8.times do |i|
    d = 0
    w = ctx.check(off, 2)
    if w
      d = w.be16(0)
    end
    off += d
  end
  Out.update(0, off & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB023 11:19
