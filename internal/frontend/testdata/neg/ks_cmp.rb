require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_k(ctx)
  if ctx.arg(2) == 7
    Out.update(0, 1)
  end
end
BPF.ksyscall :on_k, "prctl", params: {2 => :u64}
# want: SB014 6:6
