require "bpf"

# `return 1` as the last statement in a uprobe program (it was once dropped silently) — the return-free pair
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
end
BPF.uprobe :on_x, "target/cfix", "sum_args", params: {1 => :i64, 2 => :u32, 3 => :i32}
