require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Port = BPF::Config.new("Port", :u16)

def prog(ctx)
  Counts.atomic_add(0, 1)
  Port.add(1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB029 8:3
