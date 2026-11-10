require "bpf"

# `return` in an `if` arm in a fentry program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  tgid = BPF.pid_tgid >> 32
  if tgid == 1
    return
    Out.atomic_add(1, 1)
  end
  Out.atomic_add(0, 1)
end
BPF.fentry :on_x, "bpf_fentry_test1"
# want: SB008 9:5
