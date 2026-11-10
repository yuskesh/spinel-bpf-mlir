require "bpf"

R = BPF::LpmTrieMap.new("R", :u32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  R.atomic_add(1, 2)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB002 7:3
