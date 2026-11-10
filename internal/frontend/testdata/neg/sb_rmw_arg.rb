require "bpf"

Stat = Struct.new(:hits, :last)
BPF.record(Stat, hits: :u64, last: :u64)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 4)
Vals = BPF::ArrayMap.new("Vals", :u64, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)
def setv(q, x)
  q.load.hits = x & 0xFFFF
  0
end

def prog(ctx)
  p = Stats.lookup(0)
  if p
    v = p.load.hits & 0xFF
    setv(p, v + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 17:5
