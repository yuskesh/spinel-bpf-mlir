require "bpf"

# An xdp program returns a socket_filter verdict
def p(ctx)
  BPF::SF_KEEP
end
BPF.xdp :p
# want: SB028 5:3
