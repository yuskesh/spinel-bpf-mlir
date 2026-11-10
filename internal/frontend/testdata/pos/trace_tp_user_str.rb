require "bpf"




Ev = Struct.new(:nr, :pad, :name, :status)
BPF.record(Ev, nr: :i32, pad: :u32, name: [:u8, 32], status: :i64)

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(32, 0), 0), 4096)

def on_open(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = Events.output_str(Ev.new(ctx.field(:__syscall_nr), 0, Array.new(32, 0), 0), :name, ctx.str_field(:filename), :status)
      if r
        Out.atomic_add(0, 1)
      end
    end
  end
end
BPF.tracepoint :on_open, "syscalls/sys_enter_openat", fields: {__syscall_nr: [8, :i32], filename: [24, :user_str]}
