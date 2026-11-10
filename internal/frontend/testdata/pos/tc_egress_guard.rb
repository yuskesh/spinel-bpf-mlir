require "bpf"


Seen = BPF::ArrayMap.new("Seen", :u64, 2)

def filter_out(skb)
  et = 0
  w = skb.check(0, 14)
  if w
    et = w.be16(12)
  end
  return BPF::TC_DROP if et == 0x86DD
  Seen.atomic_add(0, 1)
  BPF::TC_PASS
end
BPF.tcx :filter_out, :egress
