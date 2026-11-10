require "bpf"


Stats = Struct.new(:packets, :bytes, :drops, :_pad0)
BPF.record(Stats, packets: :u64, bytes: :u64, drops: :u32, _pad0: :u32)
FlowKey = Struct.new(:proto, :_pad0, :port, :addr)
BPF.record(FlowKey, proto: :u8, _pad0: :u8, port: :u16, addr: :u32)

PerProto = BPF::PerCpuRecordMap.new("PerProto", Stats.new(0, 0, 0, 0), 8)
Hits = BPF::PerCpuArrayMap.new("Hits", :i64, 4)
PerFlow = BPF::PerCpuHashMap.new("PerFlow", FlowKey.new(0, 0, 0, 0), :u64, 64)
PerPort = BPF::PerCpuRecordHashMap.new("PerPort", :u32, Stats.new(0, 0, 0, 0), 16)

def prog(ctx)
  p = PerProto.lookup(3)
  if p
    p.load.packets += 1
    p.load.bytes += 64
    p.load.drops -= 1
  end
  h = Hits.lookup(0)
  if h
    Hits.update(0, (h.load & 0xFFFF) + 1)
  end
  s = PerFlow.add_or_init(FlowKey.new(17, 0, 53, 16909060), 1)
  if s != 0
    _ = PerPort.insert(53, Stats.new(1, 0, 0, 0))
  end
  q = PerPort.lookup(53)
  if q
    q.load.bytes += 100
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
