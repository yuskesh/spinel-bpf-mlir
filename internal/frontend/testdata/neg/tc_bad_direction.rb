require "bpf"


def p(skb)
  BPF::TC_PASS
end
BPF.tcx :p, :both
# want: SB008 7:1
