require "bpf"

# uprobe on sum_args(int64_t a, uint32_t b, int32_t c) in target/cfix: its three integer arguments (the same form as kprobe's ctx.arg)
Args = BPF::ArrayMap.new("Args", :i64, 3)

def on_sum(ctx)
  Args.update(0, ctx.arg(1))
  Args.update(1, ctx.arg(2))
  Args.update(2, ctx.arg(3))
end
BPF.uprobe :on_sum, "target/cfix", "sum_args", params: {1 => :i64, 2 => :u32, 3 => :i32}
