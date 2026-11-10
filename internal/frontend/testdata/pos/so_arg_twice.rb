require "bpf"

# repeated reads of ctx.arg: cong_avoid reads arg 2, arg 1 and arg 2 (SOArgs is [1, 2])
Out = BPF::ArrayMap.new("Out", :u32, 4)

def c_ssthresh(ctx)
  Out.atomic_add(0, 1)
  2
end

def c_undo(ctx)
  Out.atomic_add(1, 1)
  10
end

def c_avoid(ctx)
  a = ctx.arg(2) & 1
  b = ctx.arg(1) & 1
  Out.atomic_add(2 + (ctx.arg(2) & 1), a + b)
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbneg",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
