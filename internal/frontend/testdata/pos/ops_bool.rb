require "bpf"

In = BPF::ArrayMap.new("In", :i32, 2)
Out = BPF::ArrayMap.new("Out", :i64, 8)

def prog(ctx)
  p = In.lookup(0)
  if p
    a = p.load
    lt = a < 10
    both = lt && a != 3
    either = a == 0 || !(a >= 100)
    x = 1
    x += 2
    x *= 3
    if both
      x = 100
    elsif either
      x -= 1
    else
      x = 0
    end
    unless lt
      x += 5
    end
    Out.update(0, x)
    Out.update(1, both ? 1 : 0)
    Out.update(2, either ? a : -a)
    Out.update(3, (a < 0 and a > -5) ? 1 : 0)
    Out.update(4, (not lt) ? 1 : 0)
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
