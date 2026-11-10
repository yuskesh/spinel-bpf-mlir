require "bpf"

def on_m(ctx)
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 13
# want: SB008 6:1
