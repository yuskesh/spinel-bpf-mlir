require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)
Port = BPF::Config.new("Port", :u16)

def prog(ctx)
  if Port.value == 80
    Counts.atomic_add(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
x = Port.value
# want: SB003 13:5
