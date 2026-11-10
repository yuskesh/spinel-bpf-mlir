require "bpf"

# record.make of a record with an array member (Hist.new — not accepted when array members were added)
Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 4)

def prog(ctx)
  Hs.update(0, Hist.new(Array.new(8, 0), 1))
  BPF::XDP_PASS
end
BPF.xdp :prog
# want: SB024 9:16
