require "bpf"




Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Seen = BPF::ArrayMap.new("Seen", :u64, 4)

def on_sys_enter(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      nr = ctx.arg(1) & 0xFFFF_FFFF
      if nr == 110
        Seen.atomic_add(0, 1)
      elsif nr >= 1_000_000
        Seen.update(1, ctx.arg(1))
        Seen.update(2, ctx.arg(0) & 0xFFFF_FFFF)
        Seen.atomic_add(3, ctx.arg(0) >> 32)
      end
    end
  end
end
BPF.raw_tp :on_sys_enter, "sys_enter"
