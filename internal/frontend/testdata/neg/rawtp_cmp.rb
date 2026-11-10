require "bpf"

Seen = BPF::ArrayMap.new("Seen", :u64, 2)

def on_r(ctx)
  if ctx.arg(1) == 110
    Seen.update(0, 1)
  end
end
BPF.raw_tp :on_r, "sys_enter"
# want: SB014 6:6
