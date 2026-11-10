require "bpf"

# A shape bpf-mlir does not warn about: the user's if compares the index with a threshold (5) below the element count (8), the branch calls a helper (a map op), then ref.index with the same index.
# No warning (it depends on LLVM's branch elimination; bpf-mlir only documents it). A root loader accepts it, a non-root loader may reject it (this repo tests on the root host only)
Hist = Struct.new(:hist, :n)
BPF.record(Hist, hist: [:u32, 8], n: :u64)
Hs = BPF::RecordMap.new("Hs", Hist.new(Array.new(8, 0), 0), 1)
In = BPF::ArrayMap.new("In", :i32, 1)
Out = BPF::ArrayMap.new("Out", :u64, 2)

def prog(ctx)
  q = In.lookup(0)
  if q
    i = q.load
    if i >= 0 && i < 5
      Out.update(1, 1)
      p = Hs.lookup(0)
      if p
        Out.update(0, p.load.hist[i])
      end
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :prog
