require "bpf"

# + 1 on another u64 map's value stored to Out — an overflow that is not an RMW stays SB014
Out = BPF::ArrayMap.new("Out", :u64, 2)
In = BPF::ArrayMap.new("In", :u64, 2)

def prog(ctx)
  q = In.lookup(0)
  if q
    Out.update(0, q.load + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 10:19
