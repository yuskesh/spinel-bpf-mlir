require "bpf"

# BPF.tcx without a direction
def p(skb)
  BPF::TC_PASS
end
BPF.tcx :p
# want: SB008 7:1
