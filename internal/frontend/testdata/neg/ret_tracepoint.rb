require "bpf"

# `return 1` as the last statement in a tracepoint program (it was once dropped silently)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
  return 1
end
BPF.tracepoint :on_x, "syscalls/sys_enter_write", fields: {fd: [16, :u64]}
# want: SB008 8:3
