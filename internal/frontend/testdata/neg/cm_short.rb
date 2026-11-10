require "bpf"

Ev = Struct.new(:comm, :status)
BPF.record(Ev, comm: [:u8, 8], status: :i64)
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(8, 0), 0), 4096)

def on_poll(ctx)
  _ = Events.output_comm(Ev.new(Array.new(8, 0), 0), :comm, :status)
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u32}
# want: SB024 9:54
