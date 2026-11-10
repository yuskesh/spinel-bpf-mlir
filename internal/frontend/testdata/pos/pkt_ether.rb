require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 8)
Bytes = BPF::ArrayMap.new("Bytes", :u64, 4)


def ether(ctx)
  w = ctx.check(0, 14)
  if w
    et = w.be16(12)
    slot = 4
    if et == 0x0800
      slot = 0
    elsif et == 0x86DD
      slot = 1
    elsif et == 0x0806
      slot = 2
    elsif et == 0x8100
      slot = 3
    end
    Bytes.atomic_add(0, w.u8(0))
    Bytes.atomic_add(1, w.le16(0))
    Bytes.atomic_add(2, w.be32(6))
    Bytes.atomic_add(3, w.le32(10))
  else
    slot = 7
  end
  Counts.atomic_add(slot, 1)
  BPF::XDP_PASS
end
BPF.xdp :ether
