require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  a = ctx.arg(3)
  Counts.atomic_add(0, a & 1)
end
BPF.kprobe :on_t, "do_sys_poll", params: {2 => :u32}
# want: SB028 6:15
