require "bpf"

Stat = Struct.new(:hits, :last)
BPF.record(Stat, hits: :u64, last: :u64)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 4)
Vals = BPF::ArrayMap.new("Vals", :u64, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)
def inner(q)
  q.load & 0xFF
end

def outer(q)
  inner(q)
end

def prog(ctx)
  p = Vals.lookup(0)
  if p
    Out.update(0, outer(p) & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 13:9
