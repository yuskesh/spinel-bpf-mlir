require "bpf"

def on_m(ctx)
  BPF.fmod_return((ctx.arg(0) & 0xFF) + 0x8000_0000)
end
BPF.fmod_ret :on_m, "bpf_modify_return_test", nargs: 2, args: {0 => :i32}
# want: SB014 4:19
