require "bpf"

# uprobe on greet(const char *s, uint32_t n) in target/cfix. Reads s with output_str into the ring event's name (a u8 array) and
# also writes the status into the event's status (i64). Counts by the status's sign when the reservation succeeds, and in a separate slot when it fails.
Greet = Struct.new(:pid_tgid, :n, :_pad0, :status, :name)
BPF.record(Greet, pid_tgid: :u64, n: :u32, _pad0: :u32, status: :i64, name: [:u8, 32])
Events = BPF::RingBuf.new("Events", Greet.new(0, 0, 0, 0, Array.new(32, 0)), 4096)
Stats = BPF::ArrayMap.new("Stats", :u64, 3)

def on_greet(ctx)
  r = Events.output_str(Greet.new(BPF.pid_tgid, ctx.arg(2), 0, 0, Array.new(32, 0)), :name, ctx.str_arg(1), :status)
  if r
    if r.status < 0
      Stats.atomic_add(1, 1)
    else
      Stats.atomic_add(0, 1)
    end
  else
    Stats.atomic_add(2, 1)
  end
end
BPF.uprobe :on_greet, "target/cfix", "greet", params: {1 => :user_str, 2 => :u32}
