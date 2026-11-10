require "bpf"

R = BPF::LpmTrieMap.new("R", :u32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  p = R.lookup(10, 0, 0, 1)
  if p
    Out.update(0, 1)
  end
  Out.update(1, p.load)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 11:17
