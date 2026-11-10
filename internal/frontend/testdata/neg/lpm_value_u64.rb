require "bpf"

R = BPF::LpmTrieMap.new("R", :u64, 8)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB013 3:30
