require "bpf"


State = Struct.new(:hook, :pf)
BPF.kernel_type(State, "nf_hook_state", hook: :u8, pf: :u8)
StateT = BPF::KernelType.new(State.new(0, 0))
Out = BPF::ArrayMap.new("Out", :u32, 1)

def p(ctx)
  st = ctx.state(StateT)
  st = ctx.state(StateT)
  Out.update(0, st.load.hook)
  BPF::NF_ACCEPT
end
BPF.netfilter :p
# want: SB033 11:3
