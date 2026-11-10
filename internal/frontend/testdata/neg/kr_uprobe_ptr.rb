require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_k(ctx)
  Out.update(0, 1)
end
BPF.ksyscall :on_k, "prctl", params: {2 => :ptr}
# want: SB008 8:1
