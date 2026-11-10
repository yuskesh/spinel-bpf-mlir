require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.ret)
end
BPF.uretprobe :on_r, "../uprobe/target/cfix", "sum_args", ret: :i64
# want: SB008 8:1
