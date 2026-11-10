require "bpf"

# The direction must be a Symbol literal (String is not accepted)
def p(skb)
  BPF::TC_PASS
end
BPF.tcx :p, "ingress"
# want: SB008 7:1
