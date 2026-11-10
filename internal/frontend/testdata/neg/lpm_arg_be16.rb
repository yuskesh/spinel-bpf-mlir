require "bpf"

R = BPF::LpmTrieMap.new("R", :u32, 8)
Out = BPF::ArrayMap.new("Out", :i64, 2)

def prog(ctx)
  w = ctx.check(0, 34)
  if w
    p = R.lookup(w.be16(30), 0, 0, 1)
    if p
      Out.update(0, p.load)
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB014 9:18
