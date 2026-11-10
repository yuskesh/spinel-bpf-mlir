require "bpf"


Event = Struct.new(:src, :dst, :proto, :_pad0, :len, :_pad1)
BPF.record(Event, src: :u32, dst: :u32, proto: :u8, _pad0: :u8, len: :u16, _pad1: :u32)
Tick = Struct.new(:n, :ns)
BPF.record(Tick, n: :u64, ns: :u64)

Events = BPF::RingBuf.new("Events", Event.new(0, 0, 0, 0, 0, 0), 4096)
Ticks = BPF::RingBuf.new("Ticks", Tick.new(0, 0), 8192)
Drops = BPF::ArrayMap.new("Drops", :u64, 2)

def prog(ctx)
  w = ctx.check(0, 14)
  if w
    if Events.output(Event.new(w.be32(0), w.be32(4), w.u8(12), 0, w.be16(12), 0))
      Drops.atomic_add(1, 1)
    else
      Drops.atomic_add(0, 1)
    end
  end
  unless Events.output(Event.new(1, 2, 3, 0, 4, 0))
    Drops.atomic_add(0, 1)
  end
  _ = Ticks.output(Tick.new(7, BPF.ktime_ns))
  BPF::XDP_PASS
end
BPF.xdp :prog
