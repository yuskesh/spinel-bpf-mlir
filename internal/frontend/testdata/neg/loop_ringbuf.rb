require "bpf"

Ev = Struct.new(:n, :_pad0)
BPF.record(Ev, n: :u32, _pad0: :u32)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0), 4096)
Drops = BPF::ArrayMap.new("Drops", :u64, 2)


def prog(ctx)
  4.times do |i|
    unless Events.output(Ev.new(i, 0))
      Drops.atomic_add(0, 1)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB030 11:12
