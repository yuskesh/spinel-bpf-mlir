require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_k(ctx)
  i = 2
  Out.update(0, ctx.arg(i))
end
BPF.ksyscall :on_k, "prctl", params: {2 => :u64}
# want: SB028 7:17
