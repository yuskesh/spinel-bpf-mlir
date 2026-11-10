require "bpf"

Ev = Struct.new(:index, :pad, :arg, :status)
BPF.record(Ev, index: :i32, pad: :u32, arg: [:u8, 32], status: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 65536)

def on_exec(ctx)
  _ = Events.output_argv(Ev.new(0, 0, Array.new(32, 0), 0), :arg, ctx.argv_arg(2), :status, :index)
end
BPF.ksyscall :on_exec, "execve", params: {2 => :user_str_array}
# want: SB024 8:93
