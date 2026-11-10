require "bpf"

# a `name:` of 8 characters and 16 bytes (the message names the byte length and the charset)
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

BPF.struct_ops :Tcpca, "tcp_congestion_ops", name: "éééééééé",
  ssthresh: :c_ssthresh, undo_cwnd: :c_undo, cong_avoid: :c_avoid
# want: SB008 20:52
