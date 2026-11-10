require "bpf"

TcpSock = Struct.new(:snd_cwnd, :snd_ssthresh, :snd_cwnd_cnt, :snd_cwnd_clamp, :prior_cwnd)
BPF.kernel_type(TcpSock, "tcp_sock", snd_cwnd: :u32, snd_ssthresh: :u32, snd_cwnd_cnt: :u32, snd_cwnd_clamp: :u32, prior_cwnd: :u32)
TcpSockT = BPF::KernelType.new(TcpSock.new(0, 0, 0, 0, 0))
Out = BPF::ArrayMap.new("Out", :u32, 4)

def reno_init(ctx)
  Out.atomic_add(0, 1)
end

def reno_ssthresh(ctx)
  Out.atomic_add(1, 1)
  r = 2
  tp = ctx.kptr_or_null(0, TcpSockT)
  if tp
    half = tp.load.snd_cwnd >> 1
    if half > 2
      r = half
    end
  end
  r
end

def reno_undo_cwnd(ctx)
  Out.atomic_add(2, 1)
  r = 10
  tp = ctx.kptr_or_null(0, TcpSockT)
  if tp
    cwnd = tp.load.snd_cwnd
    prior = tp.load.prior_cwnd
    r = cwnd
    if cwnd < prior
      r = prior
    end
  end
  r
end

def reno_cong_avoid(ctx)
  Out.atomic_add(3, 1)
  acked = ctx.arg(2)
  tp = ctx.kptr_or_null(0, TcpSockT)
  if tp
    cwnd = tp.load.snd_cwnd
    ssth = tp.load.snd_ssthresh
    clamp = tp.load.snd_cwnd_clamp
    if cwnd < ssth
      s = cwnd + acked
      n = ssth
      if s < ssth
        n = s
      end
      m = clamp
      if n < clamp
        m = n
      end
      tp.set_field(:snd_cwnd, m)
    else
      cnt = (tp.load.snd_cwnd_cnt + acked) & 0xFFFF_FFFF
      if cnt >= cwnd
        w = cwnd + 1
        w3 = clamp
        if w < clamp
          w3 = w
        end
        tp.set_field(:snd_cwnd_cnt, (cnt - cwnd) & 0xFFFF_FFFF)
        tp.set_field(:snd_cwnd, w3)
      else
        tp.set_field(:snd_cwnd_cnt, cnt)
      end
    end
  end
end

BPF.struct_ops :RenoOps, "tcp_congestion_ops", name: "rbreno",
  init: :reno_init, ssthresh: :reno_ssthresh, cong_avoid: :reno_cong_avoid, undo_cwnd: :reno_undo_cwnd
