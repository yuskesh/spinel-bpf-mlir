require "bpf"

# ctx.kptr(0, TcpSockT) on ssthresh — the socket is read only through the null check
TcpSock = Struct.new(:snd_cwnd, :snd_ssthresh, :snd_cwnd_cnt, :snd_cwnd_clamp, :prior_cwnd)
BPF.kernel_type(TcpSock, "tcp_sock", snd_cwnd: :u32, snd_ssthresh: :u32, snd_cwnd_cnt: :u32, snd_cwnd_clamp: :u32, prior_cwnd: :u32)
TcpSockT = BPF::KernelType.new(TcpSock.new(0, 0, 0, 0, 0))
Out = BPF::ArrayMap.new("Out", :u32, 4)

def c_ssthresh(ctx)
  Out.atomic_add(0, 1)
  tp = ctx.kptr(0, TcpSockT)
  2
end

def c_undo(ctx)
  Out.atomic_add(1, 1)
  10
end

def c_avoid(ctx)
  Out.atomic_add(2, 1)
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbneg",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
# want: SB033 11:8
