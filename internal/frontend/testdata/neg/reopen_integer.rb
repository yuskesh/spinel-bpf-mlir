require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog

class Integer
  def double
    2
  end
end
# want: SB016 10:1
