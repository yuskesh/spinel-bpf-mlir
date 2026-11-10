require "bpf"

# argv: slots 0..19 of argv (2nd argument, :user_str_array) of ksyscall execve(const char *filename, const char *const *argv, …),
# one ring event each via R.output_argv (bpf-mlir expands str_at into 20 nested present levels). Only for the Filter tgid (the harness's child).
# 20 events do not tell "argv has exactly 20" from "21 or more (cut at the first 20)"
Ev = Struct.new(:index, :pad, :arg, :status)
BPF.record(Ev, index: :u32, pad: :u32, arg: [:u8, 32], status: :i64)

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 65536)

def on_exec(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      _ = Events.output_argv(Ev.new(0, 0, Array.new(32, 0), 0), :arg, ctx.argv_arg(2), :status, :index)
    end
  end
end
BPF.ksyscall :on_exec, "execve", params: {2 => :user_str_array}
