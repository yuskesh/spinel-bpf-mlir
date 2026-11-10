require "bpf"

Task = Struct.new(:pid)
BPF.kernel_type(Task, "task_struct", pid: :i32)
SockCommon = Struct.new(:skc_daddr, :owner)
BPF.kernel_type(SockCommon, "sock_common", skc_daddr: :u32, owner: [:kptr, Task])
Sock = Struct.new(:__sk_common)
BPF.kernel_type(Sock, "sock", __sk_common: [:struct, SockCommon])
SockT = BPF::KernelType.new(Sock.new(SockCommon.new(0, 0)))

Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_send(ctx)
  sk = ctx.kptr_or_null(0, SockT)
  if sk
    Out.update(0, sk.load.__sk_common.owner.pid)
  end
end
BPF.fentry :on_send, "tcp_sendmsg", args: {0 => [:or_null, SockT]}
# want: SB033 16:19
