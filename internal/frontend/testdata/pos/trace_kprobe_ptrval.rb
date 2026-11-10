require "bpf"

# The value of a kprobe pointer argument: filename of do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
# (register 2, :ptr) as its raw 64 bits in an i64 (not dereferenced). For the Filter tgid: Out[0] = filename's address,
# add 1 to Out[1], add_or_init(address, 1) on Seen (key is the :i64 address): the address used as a key
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 2)
Seen = BPF::HashMap.new("Seen", :i64, :u64, 64)

def on_open(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      a = ctx.arg(2)
      Out.update(0, a)
      Out.atomic_add(1, 1)
      _ = Seen.add_or_init(a, 1)
    end
  end
end
BPF.kprobe :on_open, "do_sys_openat2", params: {2 => :ptr, 3 => :ptr}
