require "bpf"


FlowKey = Struct.new(:proto, :_pad0, :port, :addr)
BPF.record(FlowKey, proto: :u8, _pad0: :u8, port: :u16, addr: :u32)
Stat = Struct.new(:frames, :bytes)
BPF.record(Stat, frames: :u64, bytes: :u64)

Counts = BPF::HashMap.new("Counts", :u32, :u64, 64)
Seen = BPF::LruHashMap.new("Seen", :i64, :i32, 16)
Flows = BPF::RecordHashMap.new("Flows", FlowKey.new(0, 0, 0, 0), Stat.new(0, 0), 128)
ByPort = BPF::LruRecordHashMap.new("ByPort", :u32, Stat.new(0, 0), 32)
Out = BPF::ArrayMap.new("Out", :i64, 8)

def prog(ctx)
  st = Counts.add_or_init(7, 1)
  Out.update(0, st)
  if Seen.insert(-5, 3) != 0
    Out.update(1, 1)
  end
  _ = Seen.replace(-5, 4)
  s2 = Flows.insert(FlowKey.new(17, 0, 53, 16909060), Stat.new(1, 60))
  Out.update(2, s2)
  f = Flows.lookup(FlowKey.new(17, 0, 53, 16909060))
  if f
    f.atomic_add(:frames, 1)
    f.load.bytes = 100
  end
  c = Counts.lookup(7)
  if c
    c.atomic_add(2)
    Out.update(3, c.load & 0xFFFF)
  end
  d = Counts.delete(8)
  Out.update(4, d)
  if ByPort.update(443, Stat.new(0, 0)) == BPF::E2BIG
    Out.update(5, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
