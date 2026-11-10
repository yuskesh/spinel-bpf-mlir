require "bpf"

# The delta's range lies outside i32 (a u32 map value)
D = BPF::ArrayMap.new("D", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def p(ctx)
  d = 0
  q = D.lookup(0)
  if q
    d = q.load
  end
  st = ctx.adjust_head(d)
  Out.update(0, st)
  BPF::XDP_PASS
end
BPF.xdp :p
# Predicted 13:23 (a miscounted column)
# want: SB014 13:24
