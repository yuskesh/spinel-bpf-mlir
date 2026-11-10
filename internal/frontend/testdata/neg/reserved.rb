require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog

def spinelbpf_x
  1
end
puts spinelbpf_x
# want: SB007 10:1
