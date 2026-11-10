require "bpf"

Seen = BPF::ArrayMap.new("Seen", :u64, 2)

def on_r(ctx)
  Seen.update(0, ctx.arg(1))
end
BPF.raw_tp :on_r, :sys_enter
# want: SB008 8:1
