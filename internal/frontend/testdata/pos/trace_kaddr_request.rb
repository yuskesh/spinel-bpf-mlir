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
  q = ctx.kptr_or_null(0, RqT)
  if q
    tgid = BPF.pid_tgid >> 32
    f = Filter.lookup(0)
    if f
      if f.load == tgid
        _ = Starts.update(q.addr, 1)
        r = Last.lookup(0)
        if r
          r.load.addr = q.addr
          r.load.sector = q.load.__sector
          r.load.len = q.load.__data_len
        end
        Out.atomic_add(0, 1)
      end
    end
  end
end
BPF.fentry :on_start, "blk_mq_start_request", args: {0 => [:or_null, RqT]}

def on_end(ctx)
  q = ctx.kptr_or_null(0, RqT)
  if q
    f = Filter.lookup(0)
    if f
      if f.load != 0
        s = Starts.lookup(q.addr)
        if s
          Out.atomic_add(1, 1)
        else
          Out.atomic_add(2, 1)
        end
      end
    end
  end
end
BPF.fentry :on_end, "blk_mq_end_request", args: {0 => [:or_null, RqT]}
