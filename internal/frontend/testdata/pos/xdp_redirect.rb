require "bpf"

# XDP redirect_map: into devmap Ports keyed by the low 2 bits of the frame's first byte (XDP_REDIRECT when the entry exists, otherwise
# the fallback XDP_PASS). Without a window, key 3 (the fallback unless user space fills it). User space puts Ports' ifindexes with map_put.
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
