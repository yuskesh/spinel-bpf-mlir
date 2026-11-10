require "bpf"

Task = Struct.new(:pid)
BPF.kernel_type(Task, "task_struct", pid: :i33)
# want: SB033 4:43
