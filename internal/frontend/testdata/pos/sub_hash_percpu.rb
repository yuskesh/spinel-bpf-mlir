require "bpf"

# The same shape on a per-CPU hash (caller's read → integer argument → atomic_add on the helper's borrow) is accepted (the per-CPU RMW exemption; the only program kind here is xdp)
H = BPF::PerCpuHashMap.new("H", :u32, :u64, 16)

def bump(q, d)
  q.atomic_add(d & 0xFF)
  0
end

def prog(ctx)
  p = H.lookup(1)
  if p
    v = p.load & 0xFF
    bump(p, v)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
