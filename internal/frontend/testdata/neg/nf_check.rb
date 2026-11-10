require "bpf"

# check on the netfilter context (it has no packet window)
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  w = ctx.check(0, 20)
  if w
    Out.update(0, 1)
  end
  BPF::NF_ACCEPT
end
BPF.netfilter :p
# want: SB028 7:7
