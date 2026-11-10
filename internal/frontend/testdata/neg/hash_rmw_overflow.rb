require "bpf"


H = BPF::HashMap.new("H", :u32, :u64, 16)

def prog(ctx)
  p = H.lookup(1)
  if p
    _ = H.update(1, p.load + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 9:9
