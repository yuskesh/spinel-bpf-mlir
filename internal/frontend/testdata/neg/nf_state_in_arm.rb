require "bpf"


State = Struct.new(:hook, :pf)
BPF.kernel_type(State, "nf_hook_state", hook: :u8, pf: :u8)
StateT = BPF::KernelType.new(State.new(0, 0))
Out = BPF::ArrayMap.new("Out", :u32, 2)

def p(ctx)
  k = 0
  q = Out.lookup(1)
  if q
    k = q.load
  end
  if k == 0
    st = ctx.state(StateT)
    Out.update(0, st.load.hook)
  end
  BPF::NF_ACCEPT
end
BPF.netfilter :p
# want: SB033 16:5
