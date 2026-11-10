require "bpf"

# A target given as the absolute path of a system library: the name (a user string) at the entry of libc's getaddrinfo(const char *name, …), and its return value (int).
# Start's key is the tid (the low 32 bits of pid_tgid — per thread, as bcc does). libc's binary has no DWARF, so the build-time and load-time checks use the separate DWARF found by GNU build ID (/usr/lib/debug/.build-id).
Q = Struct.new(:pid_tgid, :status, :host)
BPF.record(Q, pid_tgid: :u64, status: :i64, host: [:u8, 64])
Calls = BPF::RingBuf.new("Calls", Q.new(0, 0, Array.new(64, 0)), 65536)
R = Struct.new(:pid_tgid, :ns, :ret, :pad)
BPF.record(R, pid_tgid: :u64, ns: :i64, ret: :i32, pad: :u32)
Rets = BPF::RingBuf.new("Rets", R.new(0, 0, 0, 0), 65536)
Start = BPF::HashMap.new("Start", :i64, :u64, 10240)
Out = BPF::ArrayMap.new("Out", :i64, 3)

def on_gai(ctx)
  _ = Start.update(BPF.pid_tgid & 0xFFFF_FFFF, BPF.ktime_ns)
  r = Calls.output_str(Q.new(BPF.pid_tgid, 0, Array.new(64, 0)), :host, ctx.str_arg(1), :status)
  if r
    Out.atomic_add(0, 1)
  else
    Out.atomic_add(2, 1)
  end
end
BPF.uprobe :on_gai, "/lib/x86_64-linux-gnu/libc.so.6", "getaddrinfo", params: {1 => :user_str}

def on_gai_ret(ctx)
  t = Start.lookup(BPF.pid_tgid & 0xFFFF_FFFF)
  if t
    d = (BPF.ktime_ns & 0x7FFF_FFFF_FFFF_FFFF) - (t.load & 0x7FFF_FFFF_FFFF_FFFF)
    unless Rets.output(R.new(BPF.pid_tgid, d, ctx.ret, 0))
      Out.atomic_add(2, 1)
    end
    _ = Start.delete(BPF.pid_tgid & 0xFFFF_FFFF)
    Out.atomic_add(1, 1)
  end
end
BPF.uretprobe :on_gai_ret, "/lib/x86_64-linux-gnu/libc.so.6", "getaddrinfo", ret: :i32
