require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_k(ctx)
  Out.update(0, ctx.arg(2))
end
BPF.ksyscall :on_k, "prctl", params: {}
# want: SB008 8:1
