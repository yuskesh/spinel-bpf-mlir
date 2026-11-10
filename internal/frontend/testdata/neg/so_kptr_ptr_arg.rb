require "bpf"

# ctx.kptr_or_null(1, T) on pkts_acked — argument 1 is the ack_sample pointer
TcpSock = Struct.new(:snd_cwnd, :snd_ssthresh, :snd_cwnd_cnt, :snd_cwnd_clamp, :prior_cwnd)
BPF.kernel_type(TcpSock, "tcp_sock", snd_cwnd: :u32, snd_ssthresh: :u32, snd_cwnd_cnt: :u32, snd_cwnd_clamp: :u32, prior_cwnd: :u32)
TcpSockT = BPF::KernelType.new(TcpSock.new(0, 0, 0, 0, 0))
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
end

def c_acked(ctx)
  tp = ctx.kptr_or_null(1, TcpSockT)
  if tp
    Out.atomic_add(3, 1)
  end
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbneg",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid, pkts_acked: :c_acked
# want: SB033 24:25
