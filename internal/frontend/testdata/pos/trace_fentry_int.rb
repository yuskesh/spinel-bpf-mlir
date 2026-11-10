require "bpf"




Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 5)

def on_t6(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      Out.atomic_add(0, 1)
      Out.update(1, ctx.arg(0) & 0xFFFF_FFFF)
      Out.update(2, ctx.arg(2))
      Out.update(3, ctx.arg(3))
      Out.atomic_add(4, ctx.arg(5) & 0xFFFF_FFFF)
    end
  end
end
BPF.fentry :on_t6, "bpf_fentry_test6", args: {0 => :u64, 2 => :i16, 3 => :i32, 5 => :u64}
