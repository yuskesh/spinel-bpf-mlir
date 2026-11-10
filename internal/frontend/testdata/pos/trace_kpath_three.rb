require "bpf"



Inner = Struct.new(:v)
BPF.kernel_type(Inner, "e154_inner", v: :u32)
Mid = Struct.new(:inner)
BPF.kernel_type(Mid, "e154_mid", inner: [:struct, Inner])
Outer = Struct.new(:mid)
BPF.kernel_type(Outer, "e154_outer", mid: [:struct, Mid])
OuterT = BPF::KernelType.new(Outer.new(Mid.new(Inner.new(0))))

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_x(ctx)
  o = ctx.kptr_or_null(0, OuterT)
  if o
    Out.update(0, o.load.mid.inner.v)
  end
end
BPF.fentry :on_x, "tcp_sendmsg", args: {0 => [:or_null, OuterT]}
