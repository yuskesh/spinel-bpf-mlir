require "bpf"

# An extra argument on the flow_dissector declaration (netns is the user-side attach_netns)
def p(ctx)
  BPF::FLOW_OK
end
BPF.flow_dissector :p, :x
# want: SB008 7:1
