require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.arg(1))
end
BPF.uretprobe :on_r, "target/cfix", "sum_args", ret: :i64
# want: SB028 6:18
