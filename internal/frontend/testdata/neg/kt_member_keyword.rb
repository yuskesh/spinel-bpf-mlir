require "bpf"

Task = Struct.new(:pid, :next)
BPF.kernel_type(Task, "task_struct", pid: :i32, next: :i32)
# want: SB033 4:49
