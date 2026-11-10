require "bpf"

Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  Socks.update(0, 1)
  BPF::SK_PASS
end
BPF.sk_lookup :pick
# want: SB001 7:3
