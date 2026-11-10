require "bpf"

def on_m(ctx)
  1
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2, args: {0 => :i32}
# want: SB008 4:3
