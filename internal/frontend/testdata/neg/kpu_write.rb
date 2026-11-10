require "bpf"

SockCommon = Struct.new(:skc_daddr, :skc_dport, :skc_num)
BPF.kernel_type(SockCommon, "sock_common", skc_daddr: :u32, skc_dport: :u16, skc_num: :u16)
Sock = Struct.new(:__sk_common)
BPF.kernel_type(Sock, "sock", __sk_common: [:struct, SockCommon])
SockT = BPF::KernelType.new(Sock.new(SockCommon.new(0, 0, 0)))

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_send(ctx)
  sk = ctx.kptr_or_null(0, SockT)
  if sk
    sk.load.__sk_common.skc_num = 1
    Out.atomic_add(0, 1)
  end
end
BPF.fentry :on_send, "tcp_sendmsg", args: {0 => [:or_null, SockT]}
# want: SB033 14:5
