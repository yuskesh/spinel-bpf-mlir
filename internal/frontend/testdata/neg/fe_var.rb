require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_f(ctx)
  i = 3
  Out.update(0, ctx.arg(i))
end
BPF.fentry :on_f, "bpf_fentry_test6", args: {0 => :u64, 3 => :i32}
# want: SB033 7:17
