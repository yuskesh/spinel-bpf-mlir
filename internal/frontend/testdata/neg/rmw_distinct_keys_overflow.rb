require "bpf"

# + 1 overflow on the value under a different literal key of the same map (an accepted shape — not an RMW) stays SB014
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  p = Out.lookup(0)
  if p
    Out.update(1, p.load + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 9:19
