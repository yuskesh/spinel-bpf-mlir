require "bpf"

# An extra argument on the netfilter declaration (hook is a user-side attach argument)
def p(ctx)
  BPF::NF_ACCEPT
end
BPF.netfilter :p, :x
# want: SB008 7:1
