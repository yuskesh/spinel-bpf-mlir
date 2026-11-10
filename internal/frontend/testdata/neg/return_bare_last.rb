require "bpf"



Out = BPF::ArrayMap.new("Out", :u64, 1)

def prog(ctx)
  Out.update(0, 1)
  return
end
BPF.xdp :prog
# want: SB008 9:3
