require "bpf"


Counts = BPF::ArrayMap.new("Counts", :u64, 4)

def count_in(skb)
  w = skb.check(0, 14)
  if w
    et = w.be16(12)
    slot = 3
    if et == 0x0800
      slot = 0
    elsif et == 0x86DD
      slot = 1
    elsif et == 0x0806
      slot = 2
    end
    Counts.atomic_add(slot, 1)
  end
  BPF::TC_PASS
end
BPF.tcx :count_in, :ingress
