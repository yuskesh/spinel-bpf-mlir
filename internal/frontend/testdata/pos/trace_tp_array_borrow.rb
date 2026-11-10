require "bpf"

# A fixed byte-array tracepoint field into a record map borrow: `r.load.daddr = ctx.copy(:daddr)` (a borrow as the destination of bpf-mlir's
# ebpf.tp.field.copy). On TCP CLOSE → SYN_SENT for the Filter tgid, write the last {family, dport, daddr, daddr_v6} into Last[0] and
# add 1 to Out[0] (a body ending in a member write gets SB010 from Spinel's type probe; existing behaviour, unrelated to the copy)
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
