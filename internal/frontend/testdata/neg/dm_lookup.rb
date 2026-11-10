require "bpf"

Ports = BPF::DevMap.new("Ports", :u32, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def redir(ctx)
  p = Ports.lookup(0)
  if p
    Out.update(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :redir
# want: SB001 7:7
