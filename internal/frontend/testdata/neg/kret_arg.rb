require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.arg(1))
end
BPF.kretprobe :on_r, "do_sys_poll", ret: :i32
# want: SB028 6:18
