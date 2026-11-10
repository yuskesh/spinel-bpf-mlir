require "bpf"

# Record members whose names clash with builtin methods (b, bytes, first: String#b / String#bytes / Array#first) as operator receivers.
# Two record types (so RecordRef#load is poly, the isolated condition). The frontend accepts the boxed dispatch only when syntax and declarations show the receiver is a record member read
N = Struct.new(:b, :bytes, :first)
BPF.record(N, b: :u32, bytes: :u32, first: :u32)
Stat = Struct.new(:hits, :bytes)
BPF.record(Stat, hits: :u64, bytes: :u64)
Ns = BPF::RecordMap.new("Ns", N.new(0, 0, 0), 2)
Stats = BPF::RecordMap.new("Stats", Stat.new(0, 0), 2)
Out = BPF::ArrayMap.new("Out", :u64, 8)

def prog(ctx)
  p = Ns.lookup(0)
  if p
    Out.update(0, p.load.b & 0xFF)
    Out.update(1, p.load.bytes >> 4)
    Out.update(2, p.load.first | 1)
  end
  q = Stats.lookup(1)
  if q
    Out.update(3, q.load.bytes & 0xFFFF)
    Out.update(4, (q.load.hits & 0xFFFF_FFFF) + 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
