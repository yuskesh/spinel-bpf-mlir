require "bpf"

# `return` in a loop body in a fentry program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  3.times do |i|
    return if i == 1
    Out.atomic_add(0, 1)
  end
end
BPF.fentry :on_x, "bpf_fentry_test1"
# want: SB008 8:5
