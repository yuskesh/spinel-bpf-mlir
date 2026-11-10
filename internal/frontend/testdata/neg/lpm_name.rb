require "bpf"

R = BPF::LpmTrieMap.new("Rules", :u32, 8)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB013 3:25
