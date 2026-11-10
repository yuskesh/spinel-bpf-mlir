require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_r(ctx)
  Rets.update(0, ctx.ret)
end
BPF.uretprobe :on_r, "/bin/./true", "main", ret: :i32
# want: SB008 8:1
