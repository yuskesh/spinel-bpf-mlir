require "bpf"

Ev = Struct.new(:name, :status)
BPF.record(Ev, name: [:u8, 32], status: :i64)
Out = BPF::ArrayMap.new("Out", :i64, 1)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)

def on_k(ctx)
  Out.update(0, 1)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {2 => :user_str}
# want: SB008 11:1
