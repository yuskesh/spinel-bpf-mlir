require "bpf"

# `return 1` as the last statement in a fexit program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
  return 1
end
BPF.fexit :on_x, "bpf_fentry_test1", nargs: 1, ret: :i32
# want: SB008 8:3
