require "bpf"


Stat = Struct.new(:hits, :bytes)
BPF.record(Stat, hits: :u32, bytes: :u32)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 2)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  p = Stats.lookup(0)
  if p
    Out.update(0, (p.load.bytes & 0xFF) + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB004 12:19
