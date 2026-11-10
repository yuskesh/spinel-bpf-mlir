require "bpf"

Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  st = Socks.assign(ctx, 0)
  Out.update(0, st)
  2
end
BPF.sk_lookup :pick
# want: SB008 9:3
