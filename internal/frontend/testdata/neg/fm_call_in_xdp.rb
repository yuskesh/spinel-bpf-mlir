require "bpf"

def on_x(ctx)
  BPF::FMOD_CALL
end
BPF.xdp :on_x
# want: SB028 4:3
