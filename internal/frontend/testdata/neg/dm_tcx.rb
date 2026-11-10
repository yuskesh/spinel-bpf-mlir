require "bpf"

Ports = BPF::DevMap.new("Ports", :u32, 4)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def redir(ctx)
  Ports.redirect(0, BPF::TC_PASS)
end
BPF.tcx :redir, :ingress
# want: SB028 7:3
