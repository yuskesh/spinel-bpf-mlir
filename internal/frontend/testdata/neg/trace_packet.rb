require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  w = ctx.check(0, 14)
  Counts.atomic_add(0, 1)
end
BPF.fentry :on_t, "bpf_fentry_test1"
# want: SB028 6:7
