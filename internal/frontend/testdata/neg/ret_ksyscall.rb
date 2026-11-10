require "bpf"

# `return 1` as the last statement in a ksyscall program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
  return 1
end
BPF.ksyscall :on_x, "prctl", params: {1 => :i32}
# want: SB008 8:3
