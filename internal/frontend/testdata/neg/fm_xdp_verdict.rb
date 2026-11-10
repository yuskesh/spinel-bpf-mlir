require "bpf"

def on_m(ctx)
  BPF::XDP_PASS
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2
# want: SB028 4:3
