require "bpf"

L4 = Struct.new(:v)
BPF.kernel_type(L4, "e154_l4", v: :u32)
L3 = Struct.new(:d)
BPF.kernel_type(L3, "e154_l3", d: [:struct, L4])
L2 = Struct.new(:c)
BPF.kernel_type(L2, "e154_l2", c: [:struct, L3])
SockCommon = Struct.new(:b)
BPF.kernel_type(SockCommon, "e154_l1", b: [:struct, L2])
Sock = Struct.new(:__sk_common)
BPF.kernel_type(Sock, "sock", __sk_common: [:struct, SockCommon])
SockT = BPF::KernelType.new(Sock.new(SockCommon.new(L2.new(L3.new(L4.new(0))))))

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_send(ctx)
  sk = ctx.kptr_or_null(0, SockT)
  if sk
    Out.update(0, sk.load.__sk_common.b.c.d.v)
  end
end
BPF.fentry :on_send, "tcp_sendmsg", args: {0 => [:or_null, SockT]}
# want: SB033 20:19
