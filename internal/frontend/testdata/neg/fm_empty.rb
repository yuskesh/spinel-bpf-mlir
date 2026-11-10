require "bpf"

def on_m(ctx)
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2
# want: SB008 3:1
