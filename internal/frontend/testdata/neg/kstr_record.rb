require "bpf"

Ev = Struct.new(:name, :st)
BPF.record(Ev, name: :strptr, st: :i64)
Out = BPF::ArrayMap.new("Out", :i64, 1)

def on_x(ctx)
  Out.update(0, 1)
end
BPF.fentry :on_x, "security_bprm_check"
# want: SB024 4:22
