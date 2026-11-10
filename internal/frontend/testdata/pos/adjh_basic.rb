require "bpf"

# XDP adjust_head: delta is D[0] (set by the user or harness); the status goes to Out[0]; after the move, a new check rereads the head into Out[1] / Out[2]
D = BPF::ArrayMap.new("D", :i32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 3)

def shift(ctx)
  d = 0
  q = D.lookup(0)
  if q
    d = q.load
  end
  st = ctx.adjust_head(d)
  Out.update(0, st)
  w = ctx.check(0, 14)
  if w
    Out.update(1, w.u8(0))
    Out.update(2, w.u8(13))
  end
  BPF::XDP_PASS
end
BPF.xdp :shift
