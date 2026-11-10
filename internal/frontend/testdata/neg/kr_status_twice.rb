require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_k(ctx)
  v, st = ctx.read(3, 8, :u64)
  st = 1
  Out.update(0, st)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {2 => :ptr, 3 => :ptr}
# want: SB026 6:6
