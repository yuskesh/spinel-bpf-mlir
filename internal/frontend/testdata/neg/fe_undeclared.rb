require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_f(ctx)
  Out.update(0, ctx.arg(1) & 1)
end
BPF.fentry :on_f, "bpf_fentry_test6", args: {0 => :u64, 3 => :i32}
# want: SB033 6:25
