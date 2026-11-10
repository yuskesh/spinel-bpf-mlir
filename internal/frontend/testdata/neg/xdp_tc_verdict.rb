require "bpf"

# An xdp program returns a sched_cls verdict
def p(ctx)
  BPF::TC_PASS
end
BPF.xdp :p
# want: SB028 5:3
