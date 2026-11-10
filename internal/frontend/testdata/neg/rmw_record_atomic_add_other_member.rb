require "bpf"

S = Struct.new(:a, :b)
BPF.record(S, a: :u32, b: :u32)
R = BPF::RecordMap.new("R", S.new(0, 0), 2)

# A record member atomic_add whose delta reads another member of the same entry (stopped at entry granularity)
def prog(ctx)
  p = R.lookup(0)
  if p
    p.atomic_add(:a, p.load.b & 0xFF)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 11:5
