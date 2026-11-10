require "bpf"

Task = Struct.new(:comm)
BPF.kernel_type(Task, "task_struct", comm: [:u8, 65])
# want: SB033 4:50
