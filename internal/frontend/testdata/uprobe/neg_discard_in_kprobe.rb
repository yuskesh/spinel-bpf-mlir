require "bpf"

Greet = Struct.new(:pid_tgid, :n, :_pad0, :status, :name)
BPF.record(Greet, pid_tgid: :u64, n: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Drop = BPF::RingBuf.new("Drop", Greet.new(0, 0, 0, 0, Array.new(32, 0)), 4096)
Seen = BPF::ArrayMap.new("Seen", :i64, 4)

def on_poll(ctx)
  r = Drop.output_str_or_discard(Greet.new(BPF.pid_tgid, 0, 0, 0, Array.new(32, 0)), :name, ctx.arg(2), :status)
  if r
    Seen.update(0, 1)
  end
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u32}
# want: SB028 9:7
