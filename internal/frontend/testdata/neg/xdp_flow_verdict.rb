require "bpf"

# An xdp program returns a flow_dissector verdict
def p(ctx)
  BPF::FLOW_OK
end
BPF.xdp :p
# want: SB028 5:3
