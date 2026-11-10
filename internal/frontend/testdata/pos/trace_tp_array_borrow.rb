require "bpf"




Ev = Struct.new(:family, :dport, :daddr, :daddr_v6)
BPF.record(Ev, family: :u16, dport: :u16, daddr: [:u8, 4], daddr_v6: [:u8, 16])

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Last = BPF::RecordMap.new("Last", Ev.new(0, 0, Array.new(4, 0), Array.new(16, 0)), 1)

def on_state(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      if ctx.field(:protocol) == 6 && ctx.field(:oldstate) == 7 && ctx.field(:newstate) == 2
        r = Last.lookup(0)
        if r
          r.load.family = ctx.field(:family)
          r.load.dport = ctx.field(:dport)
          r.load.daddr = ctx.copy(:daddr)
          r.load.daddr_v6 = ctx.copy(:daddr_v6)
          Out.atomic_add(0, 1)
        end
      end
    end
  end
end
BPF.tracepoint :on_state, "sock/inet_sock_set_state", fields: {oldstate: [16, :i32], newstate: [20, :i32], dport: [26, :u16], family: [28, :u16], protocol: [30, :u16], daddr: [36, [:u8, 4]], daddr_v6: [56, [:u8, 16]]}
