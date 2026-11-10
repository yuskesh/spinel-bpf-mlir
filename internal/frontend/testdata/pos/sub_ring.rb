require "bpf"

# A helper with ring buffer output: bpf-mlir accepts ringbuf.reserve / submit in an ebpf.func body (called outside loops). Reaching it from a call inside a loop is SB030 (neg/sp_loop_ring.rb)

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
  Out.update(0, emit(7) & 1)
  BPF::XDP_PASS
end
BPF.xdp :prog
