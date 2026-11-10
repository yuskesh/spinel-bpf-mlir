require "bpf"

Ev = Struct.new(:family, :dport, :daddr, :daddr_v6)
BPF.record(Ev, family: :u16, dport: :u16, daddr: [:u32, 4], daddr_v6: [:u8, 16])

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Recs = BPF::RecordMap.new("Recs", Ev.new(0, 0, Array.new(4, 0), Array.new(16, 0)), 1)

def on_state(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = Recs.lookup(0)
      if r
        r.load.daddr = ctx.copy(:daddr)
        Out.atomic_add(0, 1)
      end
    end
  end
end
BPF.tracepoint :on_state, "sock/inet_sock_set_state",
  fields: {dport: [26, :u16], family: [28, :u16], daddr: [36, [:u8, 4]], daddr_v6: [56, [:u8, 16]]}
# want: SB028 17:9
