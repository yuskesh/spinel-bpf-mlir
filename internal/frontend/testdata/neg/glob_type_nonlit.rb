require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
T = :u16
Port = BPF::Config.new("Port", T)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB029 5:1
