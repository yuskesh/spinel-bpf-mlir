require "bpf"

# += on a shared record map is outside the per-CPU exemption (SB019)
S = Struct.new(:n, :m)
BPF.record(S, n: :u64, m: :u64)
M = BPF::RecordMap.new("M", S.new(0, 0), 2)
def prog(ctx)
  p = M.lookup(0)
  if p
    p.load.n += 1
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB019 10:5
