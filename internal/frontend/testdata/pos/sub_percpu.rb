require "bpf"



P = BPF::PerCpuArrayMap.new("P", :u64, 4)
def put(v)
  P.update(1, v & 0xFFFF)
  0
end
def prog(ctx)
  p = P.lookup(0)
  if p
    put(p.load & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
