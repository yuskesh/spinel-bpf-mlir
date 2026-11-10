require "bpf"

# an early `return if c` in a fentry program (it was once dropped silently) — the return-free pair
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  tgid = BPF.pid_tgid >> 32
  Out.atomic_add(0, 1)
end
BPF.fentry :on_x, "bpf_fentry_test1"
