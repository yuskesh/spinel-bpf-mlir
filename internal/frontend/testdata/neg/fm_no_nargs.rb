require "bpf"

def on_m(ctx)
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", args: {0 => :i32}
# want: SB008 6:1
