require "bpf"





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
