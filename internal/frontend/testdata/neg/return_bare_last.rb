require "bpf"

# Found while adding early returns: a bare return as the last statement — the frontend used to read nil and panic (present from the start), now SB008

Out = BPF::ArrayMap.new("Out", :u64, 1)

def prog(ctx)
  Out.update(0, 1)
  return
end
BPF.xdp :prog
# want: SB008 9:3
