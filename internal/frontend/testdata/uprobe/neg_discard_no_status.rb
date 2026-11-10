require "bpf"

Greet = Struct.new(:pid_tgid, :n, :_pad0, :status, :name)
BPF.record(Greet, pid_tgid: :u64, n: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Drop = BPF::RingBuf.new("Drop", Greet.new(0, 0, 0, 0, Array.new(32, 0)), 4096)
Seen = BPF::ArrayMap.new("Seen", :i64, 4)

def on_greet(ctx)
  r = Drop.output_str_or_discard(Greet.new(BPF.pid_tgid, ctx.arg(2), 0, 0, Array.new(32, 0)), :name, ctx.str_arg(1))
  if r
    Seen.update(0, 1)
  end
end
BPF.uprobe :on_greet, "target/cfix", "greet", params: {1 => :user_str, 2 => :u32}
# want: SB024 9:7
