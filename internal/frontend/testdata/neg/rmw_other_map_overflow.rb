require "bpf"


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
