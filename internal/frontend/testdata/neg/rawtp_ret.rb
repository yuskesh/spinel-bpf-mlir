require "bpf"

Seen = BPF::ArrayMap.new("Seen", :u64, 2)

def on_r(ctx)
  Seen.update(0, ctx.ret)
end
BPF.raw_tp :on_r, "sys_enter"
# want: SB028 6:18
