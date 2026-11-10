require "bpf"

# The old sp_ctx_arg.rb (an xdp ctx passed to a helper — SB034) became accepted. Now SB034 for passing a tracing kind's ctx to a helper (its reads
# depend on the attach target)
Out = BPF::ArrayMap.new("Out", :u64, 4)

def f(c)
  1
end

def on_t(ctx)
  Out.update(0, f(ctx) & 0xFF)
end
BPF.fentry :on_t, "bpf_fentry_test1"
# want: SB034 7:1
