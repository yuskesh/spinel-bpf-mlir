require "bpf"

# sk_lookup sk.assign: picks a socket from sockmap Socks keyed by local_port's low bit (st is sk_assign's status; −2 when the entry
# is missing). st goes to Out[0], the run count to Out[1]. The verdict is always SK_PASS (without a pick, the normal lookup runs). User space
# fills Socks by putting socket fds with map_put.
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
