require "bpf"

R = BPF::LpmTrieMap.new("R", :u32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  p = R.lookup(10, 0, 0, 1)
  if p
    p.atomic_add(1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 9:5
