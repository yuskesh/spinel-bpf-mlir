require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  p = Counts.lookup(0)
  if p
  elsif 1 == 1
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB005 8:3
