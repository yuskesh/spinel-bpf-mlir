require "bpf"

# An RMW shape across a borrow helper (the caller's read goes to the helper as an integer argument, the helper writes the borrowed member) is accepted for a per-CPU record map (the per-CPU RMW exemption, judged by the call site's map)

Stat = Struct.new(:hits, :last)
BPF.record(Stat, hits: :u64, last: :u64)
Stats = BPF::PerCpuRecordMap.new("Stats", Stat.new(0, 0), 4)
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
