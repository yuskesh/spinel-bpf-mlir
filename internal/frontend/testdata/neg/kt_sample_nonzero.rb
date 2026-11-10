require "bpf"

Task = Struct.new(:pid)
BPF.kernel_type(Task, "task_struct", pid: :i32)
TaskT = BPF::KernelType.new(Task.new(1))
# want: SB033 5:38
