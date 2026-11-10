require "bpf"

Task = Struct.new(:pid)
BPF.kernel_type(Task, "task_struct", pid: :i32)
TaskT = BPF::KernelType.new(Task.new(0))

def on_m(ctx)
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2, args: {0 => [:or_null, TaskT]}
# want: SB033 10:1
