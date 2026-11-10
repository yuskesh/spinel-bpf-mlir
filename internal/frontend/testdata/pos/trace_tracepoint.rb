require "bpf"




Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 3)

def on_write(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      if (ctx.field(:fd) & 0xFFFF_FFFF) == 900
        Out.atomic_add(0, 1)
        Out.update(1, ctx.field(:__syscall_nr))
        Out.atomic_add(2, ctx.field(:count) & 0xFFFF_FFFF)
      end
    end
  end
end
BPF.tracepoint :on_write, "syscalls/sys_enter_write", fields: {__syscall_nr: [8, :i32], fd: [16, :u64], count: [32, :u64]}
