require "bpf"

# each u64 intrinsic once, in a tracing program
T = BPF::ArrayMap.new("T", :u64, 8)
O = BPF::ArrayMap.new("O", :i64, 2)

def on_f(ctx)
  a = ctx.arg(0)
  b = BPF.ktime_ns
  T.update(0, BPF.u64_add(a, b))
  T.update(1, BPF.u64_sub(a, b))
  T.update(2, BPF.u64_mul(a, 3))
  w = ctx.arg(3)
  d = 1
  if w > 0
    d = w
  end
  T.update(3, BPF.u64_div(a, d))
  if BPF.time_before(a, b)
    O.update(0, 1)
  end
end

BPF.fentry :on_f, "bpf_fentry_test6", args: {0 => :u64, 3 => :i32}
