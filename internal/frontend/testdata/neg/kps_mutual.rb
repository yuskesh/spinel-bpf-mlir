require "bpf"

SockCommon = Struct.new(:skc_daddr, :skc_dport, :skc_num)
BPF.kernel_type(SockCommon, "sock_common", skc_daddr: :u32, skc_dport: :u16, skc_num: :u16)
Sock = Struct.new(:__sk_common)
BPF.kernel_type(Sock, "sock", __sk_common: [:struct, SockCommon])
Aa = Struct.new(:b)
Bb = Struct.new(:a)
BPF.kernel_type(Aa, "e154_a", b: [:struct, Bb])
BPF.kernel_type(Bb, "e154_b", a: [:struct, Aa])
SockT = BPF::KernelType.new(Sock.new(SockCommon.new(0, 0, 0)))

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_send(ctx)
  sk = ctx.kptr_or_null(0, SockT)
  if sk
    Out.update(0, sk.load.__sk_common.skc_num)
  end
end
BPF.fentry :on_send, "tcp_sendmsg", args: {0 => [:or_null, SockT]}
# want: SB033 9:1
