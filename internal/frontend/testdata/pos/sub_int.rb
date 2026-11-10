require "bpf"



In = BPF::ArrayMap.new("In", :u64, 4)
Out = BPF::ArrayMap.new("Out", :u64, 8)

def mix(a, b)
  (a * 3 + b) & 0xFFFF
end

def tally(slot, v)
  Out.atomic_add(slot & 7, v & 0xFF)
  0
end

def sum_to(n)
  s = 0
  (0...n).each do |i|
    s += i
  end
  s
end

def twice_mix(a)
  (mix(a, a) & 0xFFFF) + (mix(a, 1) & 0xFFFF)
end

def read_in(k)
  x = 0
  p = In.lookup(k)
  if p
    x = p.load & 0xFFFF
  end
  x
end

def on_xdp(ctx)
  a = read_in(0) & 0xFFFF
  Out.update(0, mix(a, 7) & 0xFFFF)
  Out.update(1, twice_mix(a & 0xFF) & 0xFFFFF)
  Out.update(2, sum_to(8) & 0xFF)
  tally(3, 1)
  BPF::XDP_PASS
end
BPF.xdp :on_xdp

def on_tc(ctx)
  b = read_in(1) & 0xFFFF
  Out.update(4, mix(b, 2) & 0xFFFF)
  tally(5, 2)
  BPF::TC_PASS
end
BPF.tcx :on_tc, :ingress
