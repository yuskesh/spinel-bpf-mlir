require "bpf"

# tcp_congestion_ops member call counts — bpf-mlir's enum set in Ruby. Out[slot] += 1 per member call;
# cwnd_event also buckets its event at 16 + min(ev, 7). ssthresh 2, undo_cwnd 10, min_tso_segs 2, sndbuf_expand 2.
Out = BPF::ArrayMap.new("Out", :u32, 32)

def cc_init(ctx)
  Out.atomic_add(0, 1)
end

def cc_ssthresh(ctx)
  Out.atomic_add(1, 1)
  2
end

def cc_undo_cwnd(ctx)
  Out.atomic_add(2, 1)
  10
end

def cc_cong_avoid(ctx)
  Out.atomic_add(3, 1)
end

def cc_set_state(ctx)
  Out.atomic_add(4, 1)
end

def cc_cwnd_event(ctx)
  Out.atomic_add(5, 1)
  ev = ctx.arg(1)
  e = 7
  if ev < 7
    e = ev
  end
  Out.atomic_add(16 + e, 1)
end

def cc_in_ack_event(ctx)
  Out.atomic_add(6, 1)
end

def cc_pkts_acked(ctx)
  Out.atomic_add(7, 1)
end

def cc_min_tso_segs(ctx)
  Out.atomic_add(8, 1)
  2
end

def cc_sndbuf_expand(ctx)
  Out.atomic_add(9, 1)
  2
end

def cc_release(ctx)
  Out.atomic_add(11, 1)
end

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "rbcount",
  init: :cc_init, ssthresh: :cc_ssthresh, undo_cwnd: :cc_undo_cwnd, cong_avoid: :cc_cong_avoid,
  set_state: :cc_set_state, cwnd_event: :cc_cwnd_event, in_ack_event: :cc_in_ack_event, pkts_acked: :cc_pkts_acked,
  min_tso_segs: :cc_min_tso_segs, sndbuf_expand: :cc_sndbuf_expand, release: :cc_release
