require "bpf"

Tick = Struct.new(:seq, :ts)
BPF.record(Tick, seq: :u64, ts: :u64)
Ticks = BPF::RingBuf.new("Ticks", Tick.new(0, 0), 8192)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def emit(seq)
  r = 0
  if Ticks.output(Tick.new(seq & 0xFFFF, BPF.ktime_ns))
    r = 1
  end
  r
end

def prog(ctx)
  4.times do |i|
    Out.update(0, emit(i) & 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 18:19
