require "bpf"

H = BPF::HashMap.new("H", :u16, :u64, 8)
def prog(ctx)
  _ = H.update(1, 2)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB013 3:27
