require "bpf"



Bprm = Struct.new(:filename)
BPF.kernel_type(Bprm, "linux_binprm", filename: :strptr)
BprmT = BPF::KernelType.new(Bprm.new(""))

Ev = Struct.new(:name, :st)
BPF.record(Ev, name: [:u8, 32], st: :i64)
Events = BPF::RingBuf.new("Events", Ev.new(Array.new(32, 0), 0), 4096)
Filter = BPF::ArrayMap.new("Filter", :u32, 1)

def on_exec(ctx)
  q = ctx.kptr_or_null(0, BprmT)
  if q
    tgid = BPF.pid_tgid >> 32
    f = Filter.lookup(0)
    if f
      if f.load == tgid
        _ = Events.output_str(Ev.new(Array.new(32, 0), 0), :name, q.str(:filename), :st)
      end
    end
  end
end
BPF.fentry :on_exec, "security_bprm_check", args: {0 => [:or_null, BprmT]}
