require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 2)

def on_k(ctx)
  r = ctx.read(3, 8, :u64)
  Out.update(0, r[1])
end
BPF.kprobe :on_k, "do_sys_openat2", params: {2 => :ptr, 3 => :ptr}
# want: SB028 6:7
