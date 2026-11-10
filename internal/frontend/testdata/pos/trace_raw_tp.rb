require "bpf"

# raw_tp: sys_enter's args[1] (the syscall number) and args[0] (the raw value of struct pt_regs *), only for the Filter tgid:
# if the number's low 32 bits are 110 (getppid) add 1 to Seen[0]; if it is 1_000_000 or more (no real syscall has it; only the test run's synthetic call)
# Seen[1] = args[1] (the u64 as is), Seen[2] = args[0]'s low 32 bits, add args[0]'s high 32 bits to Seen[3] (the same args as bpf-mlir's own raw_tp test)
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Seen = BPF::ArrayMap.new("Seen", :u64, 4)

def on_sys_enter(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      nr = ctx.arg(1) & 0xFFFF_FFFF
      if nr == 110
        Seen.atomic_add(0, 1)
      elsif nr >= 1_000_000
        Seen.update(1, ctx.arg(1))
        Seen.update(2, ctx.arg(0) & 0xFFFF_FFFF)
        Seen.atomic_add(3, ctx.arg(0) >> 32)
      end
    end
  end
end
BPF.raw_tp :on_sys_enter, "sys_enter"
