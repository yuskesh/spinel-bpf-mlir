require "bpf"

# A cross-function RMW shape (the caller's lookup read goes to the callee as an argument, the callee updates the same map) is accepted for a per-CPU map (the per-CPU RMW exemption: no two CPUs write one slot at once; judged by the call site's map)

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
