require "bpf"

Greet = Struct.new(:pid_tgid, :n, :_pad0, :status, :name)
BPF.record(Greet, pid_tgid: :u64, n: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Events = BPF::RingBuf.new("Events", Greet.new(0, 0, 0, 0, Array.new(32, 0)), 4096)
Stats = BPF::ArrayMap.new("Stats", :u64, 3)

def on_poll(ctx)
  _ = Events.output_str(Greet.new(0, 0, 0, 0, Array.new(32, 0)), :name, ctx.arg(1), :status)
end
BPF.kprobe :on_poll, "do_sys_poll", params: {1 => :u64}
# want: SB028 9:7
