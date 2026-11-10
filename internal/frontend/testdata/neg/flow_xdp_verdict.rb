require "bpf"

# flow_dissector returns an XDP verdict
def p(ctx)
  BPF::XDP_PASS
end
BPF.flow_dissector :p
# want: SB028 5:3
