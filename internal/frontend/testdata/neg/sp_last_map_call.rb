require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

# The old user_call.rb (a call to a user def — SB002) became accepted with subprograms; now SB034: a helper whose last statement is a map call (no value)
def helper
  Counts.atomic_add(0, 1)
end

def prog(ctx)
  helper
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB034 7:3
