require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.ret)
end
BPF.kretprobe :on_r, "do_sys_poll", nargs: 3, ret: :i32
# want: SB008 8:1
