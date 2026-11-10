require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.str_arg(1))
end
BPF.uretprobe :on_r, "target/cfix", "greet", ret: :u32
# want: SB028 6:18
