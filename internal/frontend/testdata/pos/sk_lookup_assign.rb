require "bpf"




Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  k = ctx.local_port & 1
  st = Socks.assign(ctx, k)
  Out.update(0, st)
  Out.atomic_add(1, 1)
  BPF::SK_PASS
end
BPF.sk_lookup :pick
