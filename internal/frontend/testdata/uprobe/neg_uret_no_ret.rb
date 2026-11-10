require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.ret)
end
BPF.uretprobe :on_r, "target/cfix", "sum_args"
# want: SB008 8:1
