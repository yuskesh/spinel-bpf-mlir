require "bpf"

Bprm = Struct.new(:filename, :argc)
BPF.kernel_type(Bprm, "linux_binprm", filename: :strptr, argc: :i32)
BprmT = BPF::KernelType.new(Bprm.new("", 0))

Ev = Struct.new(:name, :st)
BPF.record(Ev, name: [:u8, 32], st: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_x(ctx)
  _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, ctx.str_arg(1).str(:filename), :st)
end
BPF.kprobe :on_x, "do_sys_poll", params: {2 => :u32}
# want: SB028 13:61
