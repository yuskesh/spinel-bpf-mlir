require "bpf"


Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Sums = BPF::HashMap.new("Sums", :u32, :u64, 64)

def on_poll(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      _ = Sums.add_or_init(tgid, ctx.arg(2))
    end
  end
end
BPF.kprobe :on_poll, "do_sys_poll", params: {2 => :u32}
