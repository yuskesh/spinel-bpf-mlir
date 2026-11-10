require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  Counts.atomic_add(0, 1)
  BPF::XDP_PASS
end
BPF.fentry :on_t, "bpf_fentry_test1"
# want: SB028 7:3
