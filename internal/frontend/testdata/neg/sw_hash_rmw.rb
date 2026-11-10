require "bpf"

# An RMW across a helper over a shared hash borrow (caller's read → integer argument → the helper's atomic_add delta on the borrow) is SB019
H = BPF::HashMap.new("H", :u32, :u64, 16)

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
# want: SB019 15:5
