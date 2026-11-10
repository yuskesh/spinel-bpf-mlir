require "bpf"



Ports = BPF::DevMap.new("Ports", :u32, 4)

def redir(ctx)
  k = 3
  w = ctx.check(0, 14)
  if w
    k = w.u8(0) & 3
  end
  Ports.redirect(k, BPF::XDP_PASS)
end
BPF.xdp :redir
