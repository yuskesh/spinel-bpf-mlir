require "bpf"

Ev = Struct.new(:name, :status)
BPF.record(Ev, name: [:u8, 32], status: :i64)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)

def on_open(ctx)
  _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, ctx.str_arg(3), :status)
end
BPF.ksyscall :on_open, "openat", params: {2 => :user_str, 3 => :i32}
# want: SB028 9:61
