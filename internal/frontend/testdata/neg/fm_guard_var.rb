require "bpf"

def on_m(ctx)
  a = (ctx.arg(0) & 0xFF) + 1
  return BPF.fmod_return(a) if a == 2
  BPF::FMOD_CALL
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2, args: {0 => :i32}
# want: SB006 5:26
