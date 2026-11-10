require "bpf"

Ev = Struct.new(:index, :pad, :arg, :status)
BPF.record(Ev, index: :u32, pad: :u32, arg: [:u8, 32], status: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 65536)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_k(ctx)
  _ = Events.output_argv(Ev.new(0, 0, Array.new(32, 0), 0), :arg, ctx.argv_arg(2), :status, :index)
end
BPF.kprobe :on_k, "do_sys_poll", params: {2 => :u32}
# want: SB028 9:7
