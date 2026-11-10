require "bpf"

H = BPF::HashMap.new("H", :u32, :u64, 16)


def prog(ctx)
  x = 0
  p = H.lookup(1)
  if p
    x = p.load & 0xFF
  end
  _ = H.add_or_init(1, x)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 12:7
