require "bpf"

Ports = BPF::DevMap.new("Ports", :u64, 4)

def redir(ctx)
  BPF::XDP_PASS
end
BPF.xdp :redir
# want: SB013 3:34
