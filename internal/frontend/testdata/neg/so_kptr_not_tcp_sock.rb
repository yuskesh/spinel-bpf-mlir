require "bpf"

# T declared with the BTF name sock, not tcp_sock
Sk = Struct.new(:sk_mark)
BPF.kernel_type(Sk, "sock", sk_mark: :u32)
SkT = BPF::KernelType.new(Sk.new(0))
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
  Out.atomic_add(2, 1)
  tp = ctx.kptr_or_null(0, SkT)
  if tp
    Out.atomic_add(3, 1)
  end
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbneg",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
# want: SB033 21:28
