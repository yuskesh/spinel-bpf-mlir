require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def __ebpf_x(ctx)
  Out.update(0, 1)
  BPF::XDP_PASS
end
BPF.xdp :__ebpf_x
# want: SB007 5:1
