require "bpf"

Ev = Struct.new(:index, :pad, :arg, :status)
BPF.record(Ev, index: :u32, pad: :u32, arg: [:u8, 32], status: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 65536)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_exec(ctx)
  a = ctx.argv_arg(2)
  _ = Events.output_argv(Ev.new(0, 0, Array.new(32, 0), 0), :arg, a, :status, :index)
end
BPF.ksyscall :on_exec, "execve", params: {2 => :user_str_array}
# want: SB028 9:7
# want: SB028 10:67
