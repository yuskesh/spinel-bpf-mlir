require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.ret)
end
x = BPF.kretprobe(:on_r, "do_sys_poll", ret: :i32)
# want: SB008 8:5
