require "bpf"

# tracepoint: syscalls/sys_enter_write's __syscall_nr, fd and count (offsets and types from the 7.1.8 tracefs format; checked before load).
# Only for the Filter tgid with fd's low 32 bits 900: add 1 to Out[0], Out[1] = __syscall_nr, add count's low 32 bits to Out[2]
# (the same shape as bpf-mlir's own sys_enter_write test; our own stdout / stderr writes are excluded by fd, other processes by tgid)
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
