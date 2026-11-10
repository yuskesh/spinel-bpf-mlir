require "bpf"

A = BPF::ArrayMap.new("A", :u64, 1)

def first(ctx)
  A.atomic_add(0, 1)
  BPF::XDP_PASS
end

def second(c)
  BPF::XDP_TX
end
BPF.xdp :first
BPF.xdp :second
puts A.name
