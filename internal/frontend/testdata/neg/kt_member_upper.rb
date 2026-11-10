require "bpf"

Task = Struct.new(:pid, :Flags)
BPF.kernel_type(Task, "task_struct", pid: :i32, Flags: :u32)
# want: SB033 4:49
