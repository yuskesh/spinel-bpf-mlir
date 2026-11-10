require "bpf"

Bprm = Struct.new(:filename, :argc)
BPF.kernel_type(Bprm, "linux_binprm", filename: :strptr, argc: :i32)
BprmT = BPF::KernelType.new(Bprm.new(0, 0))

Ev = Struct.new(:name, :st)
BPF.record(Ev, name: [:u8, 32], st: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)
Out = BPF::ArrayMap.new("Out", :i64, 1)
def on_x(ctx)
  Out.update(0, 1)
end
BPF.fentry :on_x, "security_bprm_check"
# want: SB033 5:38
