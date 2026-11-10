require "bpf"

# `return 1` as the last statement in a kretprobe program (it was once dropped silently) — the return-free pair
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
end
BPF.kretprobe :on_x, "do_sys_poll", ret: :i32
