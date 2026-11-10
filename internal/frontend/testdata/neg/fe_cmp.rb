require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_f(ctx)
  if ctx.arg(0) == 16
    Out.update(0, 1)
  end
end
BPF.fentry :on_f, "bpf_fentry_test6", args: {0 => :u64, 3 => :i32}
# want: SB014 6:6
