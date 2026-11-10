require "bpf"


Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Calls = BPF::HashMap.new("Calls", :u32, :u64, 64)

def on_test1(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      _ = Calls.add_or_init(tgid, 1)
    end
  end
end
BPF.fentry :on_test1, "bpf_fentry_test1"
