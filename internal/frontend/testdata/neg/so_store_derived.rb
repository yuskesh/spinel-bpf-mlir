require "bpf"

# a set_field through q = tp.ptr(:f, T), a pointer of another kernel type
Sk = Struct.new(:sk_mark)
BPF.kernel_type(Sk, "sock", sk_mark: :u32)
SkT = BPF::KernelType.new(Sk.new(0))
TcpSock = Struct.new(:snd_cwnd, :sk)
BPF.kernel_type(TcpSock, "tcp_sock", snd_cwnd: :u32, sk: [:kptr, Sk])
TcpSockT = BPF::KernelType.new(TcpSock.new(0, 0))
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
  tp = ctx.kptr_or_null(0, TcpSockT)
  if tp
    q = tp.ptr(:sk, SkT)
    if q
      q.set_field(:sk_mark, 1)
    end
  end
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbneg",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
# want: SB033 28:7
