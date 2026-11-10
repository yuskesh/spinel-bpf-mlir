require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)

# An array atomic_add whose delta is a local that derives from the same entry
def prog(ctx)
  p = Out.lookup(0)
  if p
    x = p.load & 0xFF
    Out.atomic_add(0, x)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 10:5
