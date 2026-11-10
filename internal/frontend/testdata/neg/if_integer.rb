require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  if 1
    Counts.atomic_add(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 6:6
