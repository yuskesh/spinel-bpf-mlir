require "bpf"

Ev = Struct.new(:index, :pad, :arg, :status)
BPF.record(Ev, index: :u32, pad: :u32, arg: :u64, status: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, 0, 0), 65536)

def on_exec(ctx)
  _ = Events.output_argv(Ev.new(0, 0, 0, 0), :arg, ctx.argv_arg(2), :status, :index)
end
BPF.ksyscall :on_exec, "execve", params: {2 => :user_str_array}
# want: SB024 8:46
