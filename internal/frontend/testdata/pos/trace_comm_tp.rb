require "bpf"


Ev = Struct.new(:comm, :status)
BPF.record(Ev, comm: [:u8, 16], status: :i64)

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(16, 0), 0), 4096)

def on_getppid(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      _ = Events.output_comm(Ev.new(Array.new(16, 0), 0), :comm, :status)
    end
  end
end
BPF.tracepoint :on_getppid, "syscalls/sys_enter_getppid", fields: {__syscall_nr: [8, :i32]}
