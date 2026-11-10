require "bpf"

Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  _ = Socks.assign(ctx, 0)
  BPF::SK_PASS
end
BPF.sk_lookup :pick
# want: SB026 7:3
