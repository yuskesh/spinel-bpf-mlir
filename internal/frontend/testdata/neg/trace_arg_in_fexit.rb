require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def on_t(ctx)
  a = ctx.arg(1)
  Counts.atomic_add(0, 1)
end
BPF.fexit :on_t, "bpf_fentry_test1", nargs: 1, ret: :i32
# want: SB028 6:7
