require "bpf"


Seen = Struct.new(:proto, :_pad0, :len, :hits)
BPF.record(Seen, proto: :u8, _pad0: :u8, len: :u16, hits: :u32)
Pair = Struct.new(:a, :b)
BPF.record(Pair, a: :i16, b: :u16)

Last = BPF::RecordMap.new("Last", Seen.new(0, 0, 0, 0), 2)
Pairs = BPF::RecordMap.new("Pairs", Pair.new(0, 0), 2)

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    p = Last.lookup(w.u8(0) & 1)
    if p
      p.load.proto = w.u8(13)
      p.load.len = w.be16(12)
      p.atomic_add(:hits, 1)
    end
    q = Pairs.lookup(w.u8(1) & 1)
    if q
      q.load.b = w.u8(2)
    end
    Pairs.update(0, Pair.new(w.u8(3) - 128, w.be16(4)))
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
