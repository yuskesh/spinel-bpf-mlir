require "bpf"


Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Rets = BPF::ArrayMap.new("Rets", :u64, 3)

def on_ret(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      r = ctx.ret
      if r == 0
        Rets.atomic_add(0, 1)
      elsif r > 0
        Rets.atomic_add(1, 1)
      else
        Rets.atomic_add(2, 1)
      end
    end
  end
end
BPF.fexit :on_ret, "bpf_fentry_test1", nargs: 1, ret: :i32
