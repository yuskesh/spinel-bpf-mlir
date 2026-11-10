require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_k(ctx)
  Out.update(0, ctx.field(:fd) & 1)
end
BPF.ksyscall :on_k, "prctl", params: {2 => :u64}
# want: SB001 6:17
