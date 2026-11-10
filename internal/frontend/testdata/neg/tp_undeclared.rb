require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_w(ctx)
  Out.update(0, ctx.field(:buf) & 1)
end
BPF.tracepoint :on_w, "syscalls/sys_enter_write", fields: {fd: [16, :u64]}
# want: SB028 6:27
