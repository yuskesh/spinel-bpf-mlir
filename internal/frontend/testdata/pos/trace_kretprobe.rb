require "bpf"

# kretprobe: do_sys_poll's return value (int; our poll(NULL, n, 0) returns 0 for n = 0 and −14 (−EFAULT) for n > 0),
# only for the Filter tgid, into Rets[0] (last value), Rets[1] (count), Rets[2] (sum) (the same shape as bpf-mlir's own kretprobe test)
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Rets = BPF::ArrayMap.new("Rets", :i64, 3)

def on_ret_poll(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = ctx.ret
      Rets.update(0, r)
      Rets.atomic_add(1, 1)
      Rets.atomic_add(2, r)
    end
  end
end
BPF.kretprobe :on_ret_poll, "do_sys_poll", ret: :i32
