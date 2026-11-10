require "bpf"

# `return` outside the no-verdict program stays accepted — a user-side method with an early return and an xdp guard sit
# next to a fentry program without one (the walk covers only the selected program's def and its control-flow bodies).
Out = BPF::ArrayMap.new("Out", :u64, 2)
In = BPF::ArrayMap.new("In", :i32, 1)

def on_x(ctx)
  Out.atomic_add(0, 1)
end
BPF.fentry :on_x, "bpf_fentry_test1"

def on_pkt(ctx)
  k = 0
  q = In.lookup(0)
  if q
    k = q.load
  end
  return BPF::XDP_DROP if k < 0
  Out.atomic_add(1, 1)
  BPF::XDP_PASS
end
BPF.xdp :on_pkt

def describe(v)
  return "none" if v == 0
  v.to_s
end
puts describe(0)
