require "bpf"

# Write to a window (not in the API — the pair of tc_window_write.rb)
def p(ctx)
  w = ctx.check(0, 14)
  if w
    w.set_u8(0, 1)
  end
  BPF::XDP_PASS
end
BPF.xdp :p
# want: SB002 7:5
