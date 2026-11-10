require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog

t = Thread.new { 1 }
puts t.value
