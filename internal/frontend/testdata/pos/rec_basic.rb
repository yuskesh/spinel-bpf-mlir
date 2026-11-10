require "bpf"


Stat = Struct.new(:hits, :bytes, :last_len, :_pad0, :flags)
BPF.record(Stat, hits: :u64, bytes: :u64, last_len: :u16, _pad0: :u16, flags: :i32)
Pair = Struct.new(:a, :b)
BPF.record(Pair, a: :i16, b: :u16)

Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0, 0, 0, 0), 4)
Pairs = BPF::RecordMap.new("Pairs", Pair.new(0, 0), 2)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def prog(ctx)
  p = Stats.lookup(0)
  if p
    p.atomic_add(:hits, 1)
    p.atomic_add(:bytes, 64)
    p.load.last_len = 1500
    p.load.flags = -7
    Out.update(0, p.load.flags)
    Out.update(1, p.load.last_len + 1)
    Out.update(2, p.load.hits & 0xFFFF)
  end
  q = Pairs.lookup(1)
  if q
    Out.update(3, q.load.a - q.load.b)
  end
  Pairs.update(0, Pair.new(-32768, 65535))
  BPF::XDP_PASS
end
BPF.xdp :prog
