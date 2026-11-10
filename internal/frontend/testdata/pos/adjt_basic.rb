require "bpf"

# XDP adjust_tail (shrinking only): the status goes to Out[0]; if an 18-byte window still fits after shrinking, Out[1] gets 1. Also a program with delta 0 (the helper is still called)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def trim4(ctx)
  st = ctx.adjust_tail(-4)
  Out.update(0, st)
  w = ctx.check(0, 18)
  if w
    Out.update(1, 1)
  end
  BPF::XDP_PASS
end

def trim0(ctx)
  _ = ctx.adjust_tail(0)
  BPF::XDP_PASS
end
BPF.xdp :trim4
BPF.xdp :trim0
