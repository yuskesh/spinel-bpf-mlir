require "bpf"

# BPF::Scx.dsq_move_to_local(0) in a fentry program
Out = BPF::ArrayMap.new("Out", :u64, 2)

def on_x(ctx)
  Out.atomic_add(0, 1)
  BPF::Scx.dsq_move_to_local(0)
end
BPF.fentry :on_x, "bpf_fentry_test1"
# want: SB002 8:3
