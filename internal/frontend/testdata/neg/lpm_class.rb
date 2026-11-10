require "bpf"

class LpmTrieMap
end

Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  Out.update(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB011 3:1
