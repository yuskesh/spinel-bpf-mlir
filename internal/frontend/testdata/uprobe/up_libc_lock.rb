require "bpf"

# uprobe pointer argument (:ptr — a raw i64): the mutex of libc's pthread_mutex_lock(pthread_mutex_t *mutex) goes into the per-thread Held,
# and if a mutex was already held, an edge (from → to) goes into Edges. pthread_mutex_unlock sets Held to 0 without reading its argument (a one-level approximation — the deadlock shape).
E = Struct.new(:pid_tgid, :from, :to)
BPF.record(E, pid_tgid: :u64, from: :i64, to: :i64)
Edges = BPF::RingBuf.new("Edges", E.new(0, 0, 0), 65536)
Held = BPF::HashMap.new("Held", :i64, :i64, 10240)
Out = BPF::ArrayMap.new("Out", :i64, 3)

def on_lock(ctx)
  tid = BPF.pid_tgid & 0xFFFF_FFFF
  m = ctx.arg(1)
  prev = Held.lookup(tid)
  if prev
    p = prev.load
    if p != 0
      if Edges.output(E.new(BPF.pid_tgid, p, m))
        Out.atomic_add(1, 1)
      else
        Out.atomic_add(2, 1)
      end
    end
  end
  _ = Held.update(tid, m)
  Out.atomic_add(0, 1)
end
BPF.uprobe :on_lock, "/lib/x86_64-linux-gnu/libc.so.6", "pthread_mutex_lock", params: {1 => :ptr}

def on_unlock(ctx)
  _ = Held.update(BPF.pid_tgid & 0xFFFF_FFFF, 0)
end
BPF.uprobe :on_unlock, "/lib/x86_64-linux-gnu/libc.so.6", "pthread_mutex_unlock", params: {}
