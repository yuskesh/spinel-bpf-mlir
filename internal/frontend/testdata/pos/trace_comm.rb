require "bpf"

# The current task's comm: in kprobe do_sys_poll (nfds, unsigned int, register 2), for the Filter tgid, into Events
# {nfds, comm: 16 bytes from bpf_get_current_comm, status: the helper's raw status} (R.output_comm → ebpf.task.comm); on success add 1 to Out[0]
Ev = Struct.new(:nfds, :pad, :comm, :status)
BPF.record(Ev, nfds: :u32, pad: :u32, comm: [:u8, 16], status: :i64)

Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(0, 0, Array.new(16, 0), 0), 4096)

def on_poll(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = Events.output_comm(Ev.new(ctx.arg(2), 0, Array.new(16, 0), 0), :comm, :status)
      if r
        Out.atomic_add(0, 1)
      end
    end
  end
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u32}
