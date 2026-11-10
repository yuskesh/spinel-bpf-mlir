require "bpf"

Out = BPF::ArrayMap.new("Out", :u32, 2)

# The origin crosses a loop's iter_args
def prog(ctx)
  s = 0
  p = Out.lookup(0)
  if p
    v = p.load & 0xF
    4.times { s += v }
  end
  Out.update(0, s)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 13:3
