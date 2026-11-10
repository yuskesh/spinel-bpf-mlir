require "bpf"

Greet = Struct.new(:n, :_pad0, :name)
BPF.record(Greet, n: :u32, _pad0: :u32, name: [:u8, 32])
Events = BPF::RingBuf.new("Events", Greet.new(0, 0, Array.new(32, 0)), 4096)

def on_greet(ctx)
  _ = Events.output_str(Greet.new(0, 0, Array.new(32, 0)), :name, ctx.str_arg(1))
end
BPF.uprobe :on_greet, "target/cfix", "greet", params: {1 => :user_str, 2 => :u32}
# want: SB024 8:7
