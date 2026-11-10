require "bpf"

Ev = Struct.new(:name, :status)
BPF.record(Ev, name: [:u8, 32], status: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)

def on_k(ctx)
  _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, ctx.str_field(:filename), :status)
end
BPF.kprobe :on_k, "do_sys_poll", params: {2 => :u32}
# want: SB028 8:7
