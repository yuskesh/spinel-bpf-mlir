require "bpf"

Socks = BPF::SockMap.new("Socks", :u64, 2)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def pick(ctx)
  v = Socks.lookup(0)
  if v
    Out.update(0, 1)
  end
  BPF::SK_PASS
end
BPF.sk_lookup :pick
# want: SB001 7:7
