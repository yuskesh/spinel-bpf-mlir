require "bpf"

# Counter flows that are not a read-modify-write of the same object are accepted: adding to another Counter, writing a Counter value to a map, adding a map value to a Counter, adding a Config
Hits = BPF::Counter.new("Hits", :u64)
Misses = BPF::Counter.new("Misses", :u64)
Step = BPF::Config.new("Step", :u32)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  Misses.add(Hits.value & 0xFF)
  Out.update(0, Hits.value & 0xFF)
  p = Out.lookup(1)
  if p
    Hits.add(p.load & 0xFF)
  end
  Hits.add(Step.value)
  BPF::XDP_PASS
end
BPF.xdp :prog
