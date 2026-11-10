require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 8)
H = BPF::HashMap.new("H", :u32, :u64, 16)


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
