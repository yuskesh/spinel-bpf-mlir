require "bpf"

# a 15-byte ASCII name, the accepted side of the byte boundary (paired with so_name_long)
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

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "abcdefghij.k_mn",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
