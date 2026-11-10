require "bpf"

S = Struct.new(:a, :b)
BPF.record(S, a: :u32, b: :u32)
R = BPF::RecordMap.new("R", S.new(0, 0), 2)


def prog(ctx)
  p = R.lookup(0)
  if p
    x = p.load.a & 0xFFFF
    p.load.a = x + 1
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 12:5
