require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_k(ctx)
  v, _ = ctx.read(3, 8, :u64)
  Out.update(0, v & 1)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {2 => :ptr, 3 => :ptr}
# want: SB026 6:6
