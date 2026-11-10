require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)

# An array atomic_add whose delta is a direct read of the same entry (gave no diagnostic before the delta check was added)
def prog(ctx)
  p = Out.lookup(0)
  if p
    Out.atomic_add(0, p.load & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 9:5
