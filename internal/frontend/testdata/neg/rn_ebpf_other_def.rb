require "bpf"

Out = BPF::ArrayMap.new("Out", :u64, 4)

def __ebpf_other(a)
  a & 0xFF
end

def prog(ctx)
  Out.update(0, __ebpf_other(1) & 0xFF)
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB007 5:1
