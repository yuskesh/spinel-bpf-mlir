require "bpf"

Counts = BPF::ArrayMap.new("Counts", :u64, 2)

puts 1
# want: SB008 0:0
