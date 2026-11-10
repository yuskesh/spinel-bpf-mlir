require "bpf"

Ports = BPF::DevMap.new("Ports", :u32, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def redir(ctx)
  Ports.redirect(0, 2)
end
BPF.xdp :redir
# want: SB008 7:21
