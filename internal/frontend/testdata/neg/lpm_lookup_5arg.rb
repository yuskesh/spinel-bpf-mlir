require "bpf"

R = BPF::LpmTrieMap.new("R", :u32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  p = R.lookup(10, 0, 0, 1, 2)
  if p
    Out.update(0, p.load)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 7:7
