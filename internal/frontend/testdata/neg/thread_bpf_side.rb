require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  t = Thread.current
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB027 6:7
