require "bpf"

U32 = BPF::ArrayMap.new("U32", :u32, 4)
I32 = BPF::ArrayMap.new("I32", :i32, 4)
U64 = BPF::ArrayMap.new("U64", :u64, 4)
I64 = BPF::ArrayMap.new("I64", :i64, 4)

def prog(ctx)
  p = U32.lookup(1)
  if p
    u = p.load
    U32.update(0, (u + 1) & 0xFFFF_FFFF)
    I64.update(u % 4, u)
    U32.update(u & 3, 7)
  end
  q = U64.lookup(0)
  if q
    U64.update(1, q.load)
    I64.update(0, q.load & 0xFFFF)
    I64.update(1, q.load >> 1)
  end
  r = I64.lookup(2)
  if r
    I32.update(0, r.load & 0x7FFF_FFFF)
    I64.update(3, r.load / 2)
  end
  I32.update(1, -2147483648)
  I32.update(2, 2147483647)
  U64.update(3, 9223372036854775807)
  BPF::XDP_PASS
end
BPF.xdp :prog
