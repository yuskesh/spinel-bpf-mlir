require "bpf"

Greet = Struct.new(:pid_tgid, :n, :_pad0, :status, :name)
BPF.record(Greet, pid_tgid: :u64, n: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Events = BPF::RingBuf.new("Events", Greet.new(0, 0, 0, 0, Array.new(32, 0)), 4096)
Stats = BPF::ArrayMap.new("Stats", :u64, 3)

def on_greet(ctx)
  Stats.atomic_add(0, 1)
end
BPF.uprobe :on_greet, "../uprobe/target/cfix", "greet", params: {2 => :u32}
# want: SB008 11:1
