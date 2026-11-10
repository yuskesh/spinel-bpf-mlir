require "bpf"

Ev = Struct.new(:name, :status)
BPF.record(Ev, name: [:u8, 32], status: :i64)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)

def on_open(ctx)
  s = ctx.str_arg(2)
  _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, s, :status)
end
BPF.ksyscall :on_open, "openat", params: {2 => :user_str}
# want: SB028 9:7
# want: SB028 10:61
