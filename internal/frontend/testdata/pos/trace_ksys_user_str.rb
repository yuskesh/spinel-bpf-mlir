require "bpf"




Ev = Struct.new(:flags, :pad, :name, :status)
BPF.record(Ev, flags: :i32, pad: :u32, name: [:u8, 32], status: :i64)

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 4096)

def on_open(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = Events.output_str(Ev.new(ctx.arg(3), 0, Array.new(32, 0), 0), :name, ctx.str_arg(2), :status)
      if r
        Out.atomic_add(0, 1)
      end
    end
  end
end
BPF.ksyscall :on_open, "openat", params: {2 => :user_str, 3 => :i32}
