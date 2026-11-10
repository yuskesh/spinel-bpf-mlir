require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)

# Read-modify-write of the same map in a loop body (u64 + 1) — SB014 on the value expression used to come first (a gap in reason order); now the RMW is checked first: SB019
def prog(ctx)
  4.times do |i|
    p = Out.lookup(i)
    if p
      Out.update(i, p.load + 1)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 11:7
