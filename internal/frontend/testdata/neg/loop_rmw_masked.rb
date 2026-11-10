require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)

# (Control added afterwards — loop_rmw's intent) A read-modify-write of the same map with an in-range value is SB019 in a loop body too
def prog(ctx)
  4.times do |i|
    p = Out.lookup(i)
    if p
      Out.update(i, p.load & 0xFF)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 11:7
