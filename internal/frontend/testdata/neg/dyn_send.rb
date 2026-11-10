require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog
puts Counts.send(:name)
# want: SB016 9:6
