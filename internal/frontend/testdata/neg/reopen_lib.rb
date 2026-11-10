require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

def prog(ctx)
  BPF::XDP_PASS
end
BPF.xdp :prog

class BPF::ArrayMap
  def extra
    1
  end
end
# want: SB011 10:1
