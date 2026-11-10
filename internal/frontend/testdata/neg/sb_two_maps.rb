require "bpf"

Stat = Struct.new(:hits, :last)
BPF.record(Stat, hits: :u64, last: :u64)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 4)
Vals = BPF::ArrayMap.new("Vals", :u64, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)
def peek(q)
  q.load & 0xFF
end

def prog(ctx)
  p = Vals.lookup(0)
  if p
    Out.update(0, peek(p) & 0xFF)
  end
  s = Out.lookup(1)
  if s
    Out.update(2, peek(s) & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 19:24
