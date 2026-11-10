require "bpf"

Ports = BPF::DevMap.new("Ports", :u32, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def redir(ctx)
  x = 1
  if x == 1
    Ports.redirect(0, BPF::XDP_PASS)
  end
  BPF::XDP_PASS
end
BPF.xdp :redir
# want: SB002 9:5
