require "bpf"




Rq = Struct.new(:__data_len, :__sector)
BPF.kernel_type(Rq, "request", __data_len: :u32, __sector: :u64)
RqT = BPF::KernelType.new(Rq.new(0, 0))

Ev = Struct.new(:addr, :sector, :len, :pad)
BPF.record(Ev, addr: :i64, sector: :u64, len: :u32, pad: :u32)
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 4)
Starts = BPF::HashMap.new("Starts", :i64, :u64, 1024)
Last = BPF::RecordMap.new("Last", Ev.new(0, 0, 0, 0), 1)
def on_start(ctx)
  Out.update(0, ctx.addr)
end
BPF.kprobe :on_start, "blk_mq_start_request", params: {1 => :ptr}
# want: SB028 17:17
