require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    Out.update(0, w.u8(0))
  end
  w = 1
  BPF::XDP_PASS
end
BPF.xdp :prog
# Reassignment makes Spinel type w untyped (Window and Integer) — SB005 "not a Window" at the binding line (6:3); the comparator reports the gap from the uninjected side's Integer as SB010
# want: SB005 6:3
