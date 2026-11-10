require "bpf"

Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  st = Out.assign(ctx, 0)
  Out.update(0, st)
  BPF::SK_PASS
end
BPF.sk_lookup :pick
# want: SB002 7:8
