require "bpf"


def p(ctx)
  BPF::FLOW_OK
end
BPF.flow_dissector :p, :x
# want: SB008 7:1
