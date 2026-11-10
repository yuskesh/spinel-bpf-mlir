require "bpf"


Sums = BPF::HashMap.new("Sums", :u32, :u64, 64)

def on_poll(ctx)
  tgid = BPF.pid_tgid >> 32
  _ = Sums.add_or_init(tgid, ctx.arg(2) + 1)
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u16}
