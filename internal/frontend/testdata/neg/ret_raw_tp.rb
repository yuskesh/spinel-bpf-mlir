require "bpf"

# `return 1` as the last statement in a raw_tp program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
  return 1
end
BPF.raw_tp :on_x, "sys_enter"
# want: SB008 8:3
