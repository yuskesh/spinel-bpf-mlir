require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_f(ctx)
  Out.update(0, 1)
end
BPF.fentry :on_f, "bpf_fentry_test6", args: {0 => :pointer}
# want: SB033 8:1
