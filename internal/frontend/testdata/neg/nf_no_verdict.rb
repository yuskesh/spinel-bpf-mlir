require "bpf"

# A netfilter program that does not end in a verdict
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  Out.update(0, 1)
end
BPF.netfilter :p
# want: SB008 7:3
