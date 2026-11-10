require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  Counts.atomic_add(0, 1)
end
BPF.kprobe :on_t, "do_sys_poll", params: {7 => :u32}
# want: SB008 8:1
