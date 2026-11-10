require "bpf"

In = BPF::ArrayMap.new("In", :i32, 2)
Out = BPF::ArrayMap.new("Out", :i64, 16)

def prog(ctx)
  p = In.lookup(0)
  if p
    a = p.load
    Out.update(0, a + 7)
    Out.update(1, a - 2147483648)
    Out.update(2, a * a)
    Out.update(3, -a)
    Out.update(4, ~a)
    Out.update(5, a & 0xFF)
    Out.update(6, a | 0x10)
    Out.update(7, a ^ -1)
    Out.update(8, a << 31)
    Out.update(9, a >> 3)
    Out.update(10, a / 8)
    Out.update(11, a % 8)
    Out.update(12, a / -4)
    Out.update(13, a % -4)
    Out.update(14, (a & 0x7FFF) / 10)
    Out.update(15, (a & 0x7FFF) % 10)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
