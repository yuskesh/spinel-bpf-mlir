require "bpf"

# uretprobe: the return values of sum_args (returns int64_t) and greet (returns uint32_t) in target/cfix go into
# Rets[0] (last sum), Rets[1] (sum count), Rets[2] (sum total), Rets[3] (last greet), Rets[4] (greet count)
Rets = BPF::ArrayMap.new("Rets", :i64, 5)

def on_sum_ret(ctx)
  r = ctx.ret
  Rets.update(0, r)
  Rets.atomic_add(1, 1)
  Rets.atomic_add(2, r)
end
BPF.uretprobe :on_sum_ret, "target/cfix", "sum_args", ret: :i64

def on_greet_ret(ctx)
  Rets.update(3, ctx.ret)
  Rets.atomic_add(4, 1)
end
BPF.uretprobe :on_greet_ret, "target/cfix", "greet", ret: :u32
