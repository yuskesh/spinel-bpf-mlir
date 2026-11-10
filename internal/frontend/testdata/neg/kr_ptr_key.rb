require "bpf"

Out = BPF::ArrayMap.new("Out", :i64, 4)

def on_k(ctx)
  Out.update(ctx.arg(2) & 0xFF, 1)
end
BPF.kprobe :on_k, "do_sys_openat2", params: {2 => :ptr}
# want: SB020 6:14
