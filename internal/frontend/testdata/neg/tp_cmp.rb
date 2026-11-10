require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_w(ctx)
  if ctx.field(:fd) == 900
    Out.update(0, 1)
  end
end
BPF.tracepoint :on_w, "syscalls/sys_enter_write", fields: {fd: [16, :u64]}
# want: SB014 6:6
