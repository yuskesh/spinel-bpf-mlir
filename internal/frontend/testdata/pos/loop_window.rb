require "bpf"


Types = BPF::ArrayMap.new("Types", :u64, 8)
Seen = BPF::HashMap.new("Seen", :u32, :u64, 64)
Counts = BPF::ArrayMap.new("Counts", :u64, 1)

def prog(ctx)
  off = 14
  n = 0
  8.times do |i|
    t = 0
    l = 0
    w = ctx.check(off, 2)
    if w
      t = w.u8(0)
      l = w.u8(1) & 0x3F
    end
    break if t == 0
    Types.atomic_add(t & 7, 1)
    _ = Seen.add_or_init(t, 1)
    n += 1
    off += 2 + l
  end
  Counts.update(0, n)
  BPF::XDP_PASS
end
BPF.xdp :prog
