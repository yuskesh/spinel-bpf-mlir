require "bpf"

Socks = BPF::SockMap.new("Socks", :u32, 2)

def pick(ctx)
  BPF::SK_PASS
end
BPF.sk_lookup :pick
# want: SB013 3:35
