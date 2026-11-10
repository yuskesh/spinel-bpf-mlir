require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def p(ctx)
  Counts.atomic_add(0, ctx.arg(1))
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 7:24
