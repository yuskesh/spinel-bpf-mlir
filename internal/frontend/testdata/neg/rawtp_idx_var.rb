require "bpf"

Seen = BPF::ArrayMap.new("Seen", :u64, 2)

def on_r(ctx)
  i = 1
  Seen.update(0, ctx.arg(i))
end
BPF.raw_tp :on_r, "sys_enter"
# want: SB028 7:18
