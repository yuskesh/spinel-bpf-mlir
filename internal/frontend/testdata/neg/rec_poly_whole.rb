require "bpf"

# A whole record value, not a member (poly), as an operator receiver — predicted SB004, but the p.load read-shape check's SB005 comes first (same before and after the fix)
Stat = Struct.new(:hits, :bytes)
BPF.record(Stat, hits: :u32, bytes: :u32)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 2)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  p = Stats.lookup(0)
  if p
    Out.update(0, p.load & 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 12:19
