require "bpf"
# A program where an Enumerable method name (count) makes Spinel splice in its builtins; the frontend corrects the line shift and accepts it (it used to stop with SB000)

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog

def count(x)
  x + 1
end
puts count(1)
