require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_k(ctx)
  v, st = ctx.read(1, 8, :u64)
  Out.update(0, st)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {1 => :i32}
# want: SB028 6:20
