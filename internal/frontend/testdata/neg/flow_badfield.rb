require "bpf"

# A field name that struct bpf_flow_keys does not have
def p(ctx)
  return BPF::FLOW_DROP if ctx.key(:vlan) == 1
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB002 5:36
