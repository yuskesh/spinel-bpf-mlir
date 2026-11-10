require "bpf"



Stat = Struct.new(:hits, :last, :tag)
BPF.record(Stat, hits: :u64, last: :u32, tag: :u32)
Vals = BPF::ArrayMap.new("Vals", :u64, 4)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0, 0), 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def peek(q)
  q.load & 0xFFFF
end

def bump(q, d)
  q.atomic_add(d & 0xFF)
  0
end

def note(r, tag)
  r.atomic_add(:hits, 1)
  r.load.last = tag & 0xFFFF
  r.load.tag = (tag + 1) & 0xFFFF
  x = r.load.hits & 0xFFFF
  x
end

def prog(ctx)
  p = Vals.lookup(0)
  if p
    Out.update(0, peek(p) & 0xFFFF)
    bump(p, 3)
  end
  s = Stats.lookup(2)
  if s
    Out.update(1, note(s, 42) & 0xFFFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
