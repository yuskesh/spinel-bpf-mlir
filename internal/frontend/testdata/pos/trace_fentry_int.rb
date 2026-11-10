require "bpf"

# fentry integer arguments: bpf_fentry_test6(u64 a, void *b, short c, int d, void *e, u64 f) (the kernel's tracing test run calls it
# with (16, 17, 18, 19, 20, 21)). The void * arguments 1 and 4 are not declared. For the Filter tgid: add 1 to Out[0], Out[1] = low 32 bits of a,
# Out[2] = c, Out[3] = d, add the low 32 bits of f to Out[4] (sign and width are checked against FUNC_PROTO by the farg row before load)
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
