require "bpf"

Ports = BPF::DevMap.new("Ports", :u32, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def redir(ctx)
  Ports.redirect(1 == 1, BPF::XDP_PASS)
end
BPF.xdp :redir
# want: SB001 7:18
