require "bpf"
# A user-side Thread (SB012 was removed; this used to be neg/thread.rb, rejected with SB012)

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog

t = Thread.new { 1 }
puts t.value
