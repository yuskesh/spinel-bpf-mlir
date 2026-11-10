require "bpf"



NfState = Struct.new(:hook, :pf)
BPF.kernel_type(NfState, "nf_hook_state", hook: :u8, pf: :u8)
StateT = BPF::KernelType.new(NfState.new(0, 0))
Skb = Struct.new(:len)
BPF.kernel_type(Skb, "sk_buff", len: :u32)
SkbT = BPF::KernelType.new(Skb.new(0))

Out = BPF::ArrayMap.new("Out", :u32, 4)

def small_only(ctx)
  st = ctx.state(StateT)
  sk = ctx.skb(SkbT)
  n = sk.load.len
  Out.update(0, st.load.hook)
  Out.update(1, st.load.pf)
  Out.update(2, n)
  Out.atomic_add(3, 1)
  return BPF::NF_DROP if n > 64
  BPF::NF_ACCEPT
end
BPF.netfilter :small_only
