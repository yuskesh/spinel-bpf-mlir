require "bpf"

Task = Struct.new(:mm)
Mm = Struct.new(:total_vm)
BPF.kernel_type(Task, "task_struct", mm: [:kptr, Mm])
# want: SB033 5:1
