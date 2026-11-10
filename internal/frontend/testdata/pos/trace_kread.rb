require "bpf"

# Fixed-width reads behind kprobe pointer arguments: do_sys_openat2(int dfd, const char *filename, struct open_how *how).
# how is a struct open_how copied to the kernel stack (flags @0, mode @8, resolve @16; the read succeeds); filename is a user pointer
# (probe_read_kernel fails: value 0 and a negative status). For the Filter tgid with how->mode's low 32 bits 0x4511_6000 (our other opens are excluded by mode):
# add 1 to Out[0], Out[1] = resolve's low 8 bits, Out[2] = resolve's read status, Out[3] = filename's read status, Out[4] = its value
Filter = BPF::ArrayMap.new("Filter", :u32, 1)
Out = BPF::ArrayMap.new("Out", :i64, 5)

def on_open(ctx)
  tgid = BPF.pid_tgid >> 32
  f = Filter.lookup(0)
  if f
    if f.load == tgid
      m, mst = ctx.read(3, 8, :u64)
      if mst == 0
        if (m & 0xFFFF_FFFF) == 0x4511_6000
          r, rst = ctx.read(3, 16, :u64)
          c, cst = ctx.read(2, 0, :u8)
          Out.atomic_add(0, 1)
          Out.update(1, r & 0xFF)
          Out.update(2, rst)
          Out.update(3, cst)
          Out.update(4, c)
        end
      end
    end
  end
end
BPF.kprobe :on_open, "do_sys_openat2", params: {2 => :ptr, 3 => :ptr}
