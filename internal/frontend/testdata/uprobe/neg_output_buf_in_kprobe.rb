require "bpf"

W = Struct.new(:pid_tgid, :status, :count, :len, :data)
BPF.record(W, pid_tgid: :u64, status: :i64, count: :i32, len: :i32, data: [:u8, 64])
Writes = BPF::RingBuf.new("Writes", W.new(0, 0, 0, 0, Array.new(64, 0)), 65536)

def on_k(ctx)
  _ = Writes.output_buf(W.new(BPF.pid_tgid, 0, 0, 0, Array.new(64, 0)), :data, ctx.buf_arg(1), 8, :status, :count)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {1 => :i32}
# want: SB028 8:7
