require "bpf"

E = Struct.new(:a, :_pad0, :b)
BPF.record(E, a: :u8, _pad0: :u8, b: :u16)
O = Struct.new(:x)
BPF.record(O, x: :u32)
Events = BPF::RingBuf.new("Events", 0, 4096)
Drops = BPF::ArrayMap.new("Drops", :u64, 2)

def prog(ctx)
  _ = Events.output(E.new(1, 0, 2))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 7:37
