require "bpf"

def on_m(ctx)
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2, args: {2 => :i32}
# want: SB033 6:1
