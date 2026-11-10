require "bpf"

# A negative value for sport (u16)
def p(ctx)
  ctx.set_key(:sport, -1)
  BPF::FLOW_OK
end
BPF.flow_dissector :p
# want: SB014 5:23
