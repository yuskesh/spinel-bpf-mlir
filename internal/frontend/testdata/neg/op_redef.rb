require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  Counts.atomic_add(0, 1 + 1)
  BPF::XDP_PASS
end
BPF.xdp :prog

class Integer
  def +(o)
    42
  end
end
# want: SB016 11:1
