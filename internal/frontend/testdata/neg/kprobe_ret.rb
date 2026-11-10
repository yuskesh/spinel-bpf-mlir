require "bpf"

Rets = BPF::ArrayMap.new("Rets", :i64, 2)

def on_k(ctx)
  Rets.update(0, ctx.ret)
end
BPF.kprobe :on_k, "do_sys_poll", params: {2 => :u32}
# want: SB028 6:18
