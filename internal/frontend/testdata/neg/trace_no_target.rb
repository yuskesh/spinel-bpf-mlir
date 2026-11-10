require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  Counts.atomic_add(0, 1)
end
BPF.fentry :on_t
# want: SB008 8:1
