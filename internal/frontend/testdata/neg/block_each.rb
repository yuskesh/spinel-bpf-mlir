require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  [1].each { |x| x }
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 6:3
# (Was SB002, now SB030: the bounded-loop shape check names a block-taking each first — same position)
