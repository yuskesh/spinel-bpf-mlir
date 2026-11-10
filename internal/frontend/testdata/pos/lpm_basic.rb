require "bpf"


Rules = BPF::LpmTrieMap.new("Rules", :u32, 64)
Signed = BPF::LpmTrieMap.new("Signed", :i32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 4)

def ipdeny(ctx)
  deny = false
  w = ctx.check(0, 34)
  if w
    hit = false
    v = 0
    p = Rules.lookup(w.u8(30), w.u8(31), w.u8(32), w.u8(33))
    if p
      hit = true
      v = p.load
    end
    q = Signed.lookup(10, 0, 0, w.u8(33))
    if q
      Out.update(2, q.load)
    end
    Out.update(1, v)
    if hit
      Out.atomic_add(0, 1)
      if v == 1
        deny = true
      end
    end
  end
  return BPF::XDP_DROP if deny
  BPF::XDP_PASS
end

BPF.xdp :ipdeny
