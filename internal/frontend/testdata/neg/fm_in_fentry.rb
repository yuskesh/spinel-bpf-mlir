require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_f(ctx)
  Out.update(0, 1)
  BPF.fmod_return(1)
end
BPF.fentry :on_f, "bpf_fentry_test1"
# want: SB028 7:3
