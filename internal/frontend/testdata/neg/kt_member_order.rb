require "bpf"

Task = Struct.new(:pid, :tgid)
BPF.kernel_type(Task, "task_struct", tgid: :i32, pid: :i32)
# want: SB033 4:1
