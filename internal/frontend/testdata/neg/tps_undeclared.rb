require "bpf"

Ev = Struct.new(:name, :status)
BPF.record(Ev, name: [:u8, 32], status: :i64)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)

def on_open(ctx)
  _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, ctx.str_field(:pathname), :status)
end
BPF.tracepoint :on_open, "syscalls/sys_enter_openat", fields: {filename: [24, :user_str]}
# want: SB028 9:75
