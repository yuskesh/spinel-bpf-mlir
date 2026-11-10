# bpf — the eBPF-side API of spinel-bpf-mlir.
#
# Meaningful only inside eBPF-side functions (defs declared with BPF.xdp). The spinelbpf frontend matches each callee (the callee in Spinel's inferred codegen)
# against the defs in this file and maps it to an ebpf dialect op (the match is by file, not by name).
# Calling an eBPF-side method in user space stops the build with frontend error SB003, and at run time BPF.ebpf_only raises naming the method.
# Stubs are not written to raise unconditionally: if Spinel sees that, it treats the following statements as unreachable and their types vanish (observed in a probe).
module BPF
  XDP_ABORTED = 0
  XDP_DROP = 1
  XDP_PASS = 2
  XDP_TX = 3

  # sched_cls (tcx) verdicts (values are the UAPI TC_ACT_OK / TC_ACT_SHOT = TCX_PASS / TCX_DROP of tcx_action_base). Do not mix with the XDP constants (frontend error SB028)
  TC_PASS = 0
  TC_DROP = 2

  # socket_filter verdicts (keep is the u32 maximum (accept every byte) read as int32, i.e. −1, spelled like the test run's retval; drop is 0). Do not mix with other kinds' constants (frontend error SB028)
  SF_KEEP = -1
  SF_DROP = 0

  # cgroup_skb verdicts (allow is 1 (send / receive), deny is 0 (drop; an egress sender gets EPERM)). The egress-only cn values (2 / 3) are not provided. Do not mix with other kinds' constants (frontend error SB028)
  CG_ALLOW = 1
  CG_DENY = 0

  # netfilter verdicts (Linux NF_ACCEPT 1 / NF_DROP 0; a drop at LOCAL_OUT gives the sender EPERM). Do not mix with other kinds' constants (frontend error SB028)
  NF_ACCEPT = 1
  NF_DROP = 0

  # fmod_ret return value (0 calls the original function). Override the value with `BPF.fmod_return(e)` (e's range must exclude 0 — frontend error SB014).
  # An integer as the implicit last expression is not accepted (frontend error SB008). Do not mix with other kinds' constants (frontend error SB028)
  FMOD_CALL = 0

  # flow_dissector verdicts (BPF_OK 0, BPF_DROP 2, BPF_FLOW_DISSECTOR_CONTINUE 129). Do not mix with other kinds' constants (frontend error SB028)
  FLOW_OK = 0
  FLOW_DROP = 2
  FLOW_CONTINUE = 129

  # sk_lookup verdicts (SK_DROP 0, SK_PASS 1). Do not mix with other kinds' constants (frontend error SB028)
  SK_PASS = 1
  SK_DROP = 0

  # Write statuses of the hash-family maps (negative errno; compare with the status directly. Values are the Linux errno values; a test checks them against CRuby's Errno)
  ENOENT = -2
  E2BIG = -7
  ENOMEM = -12
  EEXIST = -17

  def self.ebpf_only(what)
    if what.length > 0
      raise "#{what} is eBPF-side only (call it inside a BPF.xdp program)"
    end
    0
  end

  # The xdp context (xdp_md). Reads go only through the window inside the `if w` right after `w = ctx.check(off, len)` (the API has no unchecked read).
  class XdpMd
    # Checks the packet range [off, off + len). Inside the packet it returns a Window, outside nil (branch with `if w`). len is an Integer literal.
    def check(off, len)
      if BPF.ebpf_only("BPF::XdpMd#check") == 0
        return Window.new
      end
      nil
    end

    # ingress_ifindex of xdp_md (u32; the xdp row of bpf-mlir's context-access table allows reads only)
    def ingress_ifindex
      BPF.ebpf_only("BPF::XdpMd#ingress_ifindex")
    end

    # Moves the packet start by d bytes (positive shrinks, negative grows; status is 0 or −errno). Only as `st = ctx.adjust_head(d)` or `_ = …`, as a top-level statement of the program body
    # (re-read the moved packet with a new `ctx.check`)
    def adjust_head(d)
      BPF.ebpf_only("BPF::XdpMd#adjust_head")
    end

    # Shrinks the packet tail (k is only an Integer literal ≤ 0; status is 0 or −errno). Like adjust_head, only as a top-level statement of the body
    def adjust_tail(k)
      BPF.ebpf_only("BPF::XdpMd#adjust_tail")
    end
  end

  # The sched_cls (tcx) context (__sk_buff). As with XdpMd, reads go only through the window inside the `if w` right after `w = skb.check(off, len)`
  # (bpf-mlir's sched_cls window is read-only; Window has no write API).
  class SkBuff
    def check(off, len)
      if BPF.ebpf_only("BPF::SkBuff#check") == 0
        return Window.new
      end
      nil
    end

    # len and mark of __sk_buff (u32). mark is writable (only as the statement `skb.mark = v`; v's range must fit u32, otherwise SB014)
    def len
      BPF.ebpf_only("BPF::SkBuff#len")
    end

    def mark
      BPF.ebpf_only("BPF::SkBuff#mark")
    end

    def mark=(v)
      BPF.ebpf_only("BPF::SkBuff#mark=")
    end
  end

  # Global variables (read by the frontend; at run time only on the eBPF side).
  #   X = BPF::Config.new("X", :u16)          .rodata — a value is required at load (otherwise SpinelBPF::ConfigNotSet)
  #   X = BPF::OptionalConfig.new("X", :u8)   .rodata — 0 when not given at load
  #   X = BPF::Counter.new("X", :u64)         .bss — :u32 / :u64 / :i32 / :i64; the eBPF-side add(d) is atomic (u32 / u64 use the i32 / i64 atomic_add with the same bits —
  #                                            the sign of a read is the user side's type). A counter is monotonic from load (wrapping at its width); reset it to 0 by loading again
  class Config
    def initialize(name, type)
      @name = name
      @type = type.to_s
    end

    # global_name / global_type are read by the user-space library (the name and the type's name)
    def global_name
      @name
    end

    def global_type
      @type
    end

    def value
      BPF.ebpf_only("BPF::Config#value")
    end
  end

  class OptionalConfig
    def initialize(name, type)
      @name = name
      @type = type.to_s
    end

    # global_name / global_type are read by the user-space library (the name and the type's name)
    def global_name
      @name
    end

    def global_type
      @type
    end

    def value
      BPF.ebpf_only("BPF::OptionalConfig#value")
    end
  end

  class Counter
    def initialize(name, type)
      @name = name
      @type = type.to_s
    end

    # global_name / global_type are read by the user-space library (the name and the type's name)
    def global_name
      @name
    end

    def global_type
      @type
    end

    def value
      BPF.ebpf_only("BPF::Counter#value")
    end

    def add(d)
      BPF.ebpf_only("BPF::Counter#add")
    end
  end

  # Tracing contexts. fentry has nothing to read (helpers only), fexit has ctx.ret (the declared ret type), kprobe has ctx.arg(n) (n and type from the declared params).
  # The fentry context: a struct argument declared with `args:` is read as `q = ctx.kptr_or_null(i, T)` followed by `if q` (an fentry
  # pointer may always be NULL). An integer argument is `ctx.arg(i)` (of the declared type).
  class FentryCtx
    def arg(i)
      BPF.ebpf_only("BPF::FentryCtx#arg")
    end

    def kptr_or_null(i, t)
      if BPF.ebpf_only("BPF::FentryCtx#kptr_or_null") == 0
        return KPtr.new(t.sample)
      end
      nil
    end
  end

  class FexitCtx
    def ret
      BPF.ebpf_only("BPF::FexitCtx#ret")
    end
  end

  # The fmod_ret context: an integer argument is `ctx.arg(i)` (the declared type; the same ebpf.ctx.arg as fentry)
  class FmodRetCtx
    def arg(i)
      BPF.ebpf_only("BPF::FmodRetCtx#arg")
    end
  end

  class KprobeCtx
    def arg(n)
      BPF.ebpf_only("BPF::KprobeCtx#arg")
    end

    # `v, st = ctx.read(n, offset, :type)` — the fixed-width value at offset behind the :ptr argument n, and the raw status (0 on success; negative on failure, with value 0)
    def read(n, offset, type)
      z = BPF.ebpf_only("BPF::KprobeCtx#read")
      [z, z] # the type is an Array of two Integers (the right side of a multiple assignment)
    end
  end

  # The uretprobe context. ctx.ret is the target function's return-value register (at the declared ret: width)
  class UretprobeCtx
    def ret
      BPF.ebpf_only("BPF::UretprobeCtx#ret")
    end
  end

  # The ksyscall context. ctx.arg(n) is the syscall's n-th argument from the declared params (1-based; the syscall convention, the 4th is r10)
  class KsyscallCtx
    def arg(n)
      BPF.ebpf_only("BPF::KsyscallCtx#arg")
    end

    # A :user_str argument (const char *) — only as the 3rd argument of R.output_str (as with uprobe's str_arg)
    def str_arg(n)
      if BPF.ebpf_only("BPF::KsyscallCtx#str_arg") == 0
        return UserStr.new
      end
      UserStr.new
    end

    # A :user_str_array argument (argv) — only as the 3rd argument of R.output_argv
    def argv_arg(n)
      if BPF.ebpf_only("BPF::KsyscallCtx#argv_arg") == 0
        return UserStrArray.new
      end
      UserStrArray.new
    end
  end

  # The tracepoint context. ctx.field(:name) is an event field from the declared fields (the declared type; offset and type are checked against tracefs before load)
  class TracepointCtx
    def field(name)
      BPF.ebpf_only("BPF::TracepointCtx#field")
    end

    # A :user_str field (char *) — only as the 3rd argument of R.output_str (as with uprobe's str_arg)
    def str_field(name)
      if BPF.ebpf_only("BPF::TracepointCtx#str_field") == 0
        return UserStr.new
      end
      UserStr.new
    end

    # A :user_str_array field (char **, argv) — only as the 3rd argument of R.output_argv
    def argv_field(name)
      if BPF.ebpf_only("BPF::TracepointCtx#argv_field") == 0
        return UserStrArray.new
      end
      UserStrArray.new
    end

    # A copy of a fixed byte-array field (`[off, [:u8, N]]`) — only as an array-member argument of S.new in R.output or as `r.load.m = ctx.copy(:f)` (like t.copy)
    def copy(name)
      BPF.ebpf_only("BPF::TracepointCtx#copy")
      Array.new(0, 0)
    end
  end

  # The raw_tp context. ctx.arg(i) is the tracepoint's args[i] (0-based, a literal in 0..11) — the type is always u64 (the kernel does not check it)
  class RawTpCtx
    def arg(i)
      BPF.ebpf_only("BPF::RawTpCtx#arg")
    end
  end

  # The kretprobe context. ctx.ret is the function's return-value register (at the declared ret: width; the kernel does not check the type)
  class KretprobeCtx
    def ret
      BPF.ebpf_only("BPF::KretprobeCtx#ret")
    end
  end

  # The cgroup_skb context (__sk_buff). Reads are, as with SkBuff, the window inside the `if w` right after `w = skb.check(off, len)` (read-only) and skb.len (u32).
  # **The packet starts at the network header** (no Ethernet header — window offset 0 is the start of the IPv4 header).
  class CgroupSkb
    def check(off, len)
      if BPF.ebpf_only("BPF::CgroupSkb#check") == 0
        return Window.new
      end
      nil
    end

    def len
      BPF.ebpf_only("BPF::CgroupSkb#len")
    end
  end

  # The socket_filter context (__sk_buff). Only ctx.len (the packet length, u32) is readable (bpf-mlir v1.14.0's socket_filter has no packet access).
  class SocketFilterCtx
    def len
      BPF.ebpf_only("BPF::SocketFilterCtx#len")
    end
  end

  # The uprobe context. ctx.arg(n) is an integer argument from the declared params, ctx.str_arg(n) a :user_str argument (BPF::UserStr — a type separate from integers,
  # so that each method keeps a single return type). str_arg may appear only as the 3rd argument of RingBuf#output_str.
  class UprobeCtx
    def arg(n)
      BPF.ebpf_only("BPF::UprobeCtx#arg")
    end

    def str_arg(n)
      if BPF.ebpf_only("BPF::UprobeCtx#str_arg") == 0
        return UserStr.new
      end
      UserStr.new
    end

    # A :user_buf argument (BPF::UserBuf — a type separate from integers) — only as the 3rd argument of RingBuf#output_buf
    def buf_arg(n)
      if BPF.ebpf_only("BPF::UprobeCtx#buf_arg") == 0
        return UserBuf.new
      end
      UserBuf.new
    end
  end

  # A sample of a CO-RE (compile once, run everywhere) kernel struct type (`TaskT = BPF::KernelType.new(Task.new(0, …))`). The frontend takes the type from the declaration (BPF.kernel_type);
  # the sample exists for Spinel's typing (the return type of KPtr#load).
  class KernelType
    def initialize(sample)
      @sample = sample
    end

    def sample
      @sample
    end
  end

  # A pointer to a kernel struct. `t.load.m` reads an integer field (CO-RE — ebpf.kfield.load), `t.ptr(:m, T)` a pointer field
  # (nullable), `t.copy(:m)` copies an array field. It cannot be used as a value (the frontend stops).
  class KPtr
    def initialize(value)
      @value = value
    end

    def load
      BPF.ebpf_only("BPF::KPtr#load")
      @value
    end

    def ptr(field, t)
      if BPF.ebpf_only("BPF::KPtr#ptr") == 0
        return KPtr.new(t.sample)
      end
      nil
    end

    def copy(field)
      BPF.ebpf_only("BPF::KPtr#copy")
      Array.new(0, 0)
    end

    # All 64 bits of a checked kernel pointer's address (bpf-mlir's ebpf.kptr.addr) — an integer for map keys, events and comparisons.
    # It does not read the pointee, cannot be turned back into a pointer, and does not tell apart reuse after a free
    def addr
      BPF.ebpf_only("BPF::KPtr#addr")
      0
    end

    # The kernel string behind a `:strptr` field (char *) — may appear only as the 3rd argument of RingBuf#output_str (ebpf.kernel.read_str)
    def str(field)
      if BPF.ebpf_only("BPF::KPtr#str") == 0
        return UserStr.new
      end
      UserStr.new
    end
  end

  # The tp_btf context. `ctx.kptr(i, T)` is a non-null struct argument, `ctx.kptr_or_null(i, T)` a nullable one (followed by `if`),
  # `ctx.arg(i)` an integer argument (typed by the args declaration of BPF.tp_btf).
  # The flow_dissector context (__sk_buff). The packet is the window inside the `if w` right after `w = ctx.check(off, len)` (read-only; data starts at the Ethernet header);
  # output goes to the flow_keys fields: read with `ctx.key(:f)` / `ctx.key(:ipv6_src, i)`, write with the statements `ctx.set_key(:f, v)` / `ctx.set_key(:ipv6_src, i, v)`
  # (f is a Symbol naming a struct bpf_flow_keys field; addresses and ports are raw network order — the byte order as is, not converted).
  class FlowCtx
    def check(off, len)
      if BPF.ebpf_only("BPF::FlowCtx#check") == 0
        return Window.new
      end
      nil
    end

    def key(f, i = 0)
      BPF.ebpf_only("BPF::FlowCtx#key")
    end

    def set_key(f, a, b = 0)
      BPF.ebpf_only("BPF::FlowCtx#set_key")
      nil
    end
  end

  # The netfilter context (bpf_nf_ctx). Bind `st = ctx.state(T)` (nf_hook_state) and `sk = ctx.skb(T)` (sk_buff) as top-level statements of the program body;
  # read with `st.load.hook` etc. (members declared with BPF.kernel_type — CO-RE). There is no packet window.
  class NfCtx
    def state(t)
      BPF.ebpf_only("BPF::NfCtx#state")
      KPtr.new(t.sample)
    end

    def skb(t)
      BPF.ebpf_only("BPF::NfCtx#skb")
      KPtr.new(t.sample)
    end
  end

  class TpBtfCtx
    def kptr(i, t)
      BPF.ebpf_only("BPF::TpBtfCtx#kptr")
      KPtr.new(t.sample)
    end

    def kptr_or_null(i, t)
      if BPF.ebpf_only("BPF::TpBtfCtx#kptr_or_null") == 0
        return KPtr.new(t.sample)
      end
      nil
    end

    def arg(i)
      BPF.ebpf_only("BPF::TpBtfCtx#arg")
    end
  end

  # A pointer to a user string (read only through RingBuf#output_str).
  class UserStr
  end

  # A user array of char * (argv) — only as the 3rd argument of R.output_argv
  class UserStrArray
  end

  # The address of a uprobe's user buffer (read only through RingBuf#output_buf — bpf-mlir's user.read)
  class UserBuf
  end

  # The result of RingBuf#output_str (only when the reservation succeeded — read r.status inside the `if r` right after `r = R.output_str(…)`).
  # status is probe_read_user_str's raw status: the length including the NUL, the field size when truncated, a negative errno on failure (an empty string gives 1 or 0 depending on the kernel version —
  # test for empty with `status >= 0 && field[0] == 0`; on failure the field is zero-filled, the same bytes as empty — only status tells them apart).
  class OutputStr
    def status
      BPF.ebpf_only("BPF::OutputStr#status")
    end

    # sent tells whether the event was submitted (always true for output_str; false for output_str_or_discard when it discarded on status < 0)
    def sent
      BPF.ebpf_only("BPF::OutputStr#sent") == 0
    end
  end

  # A checked packet window (readable only inside `if w`). The index i is an Integer literal with i + width <= len.
  # Multi-byte reads name the byte order (be = network order, le = little endian). Values are Integers (unsigned).
  class Window
    def u8(i)
      BPF.ebpf_only("BPF::Window#u8")
    end

    def be16(i)
      BPF.ebpf_only("BPF::Window#be16")
    end

    def be32(i)
      BPF.ebpf_only("BPF::Window#be32")
    end

    def le16(i)
      BPF.ebpf_only("BPF::Window#le16")
    end

    def le32(i)
      BPF.ebpf_only("BPF::Window#le32")
    end
  end

  # A lookup result (load only when present — inside `if p`).
  class MapRef
    def load
      BPF.ebpf_only("BPF::MapRef#load")
    end

    # atomic_add atomically adds to the value of a present borrow (only where the key exists).
    def atomic_add(delta)
      BPF.ebpf_only("BPF::MapRef#atomic_add")
    end
  end

  # An array map. The key is u32; the value type is :u32 / :u64 / :i32 / :i64.
  class ArrayMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
    end

    def name
      @name
    end

    def value_type
      @value_type.to_s # String for every map class (a Symbol index goes wrong under the library's polymorphic arguments)
    end

    # record? lets the user-space library tell integer maps from record maps.
    def record?
      false
    end

    # kind and key_type are spelled as in maps.json (the declaration JSON of the user-space library).
    def kind
      "array"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end


    def max_entries
      @max_entries
    end

    def atomic_add(key, delta)
      BPF.ebpf_only("BPF::ArrayMap#atomic_add")
    end

    def update(key, value)
      BPF.ebpf_only("BPF::ArrayMap#update")
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::ArrayMap#lookup") == 0
        return MapRef.new
      end
      nil
    end
  end

  # pid_tgid is the current task's tgid << 32 | pid (u64 — as with ktime_ns, the eBPF side only copies it to a u64, or applies `& M` / `>> K`).
  def self.pid_tgid
    BPF.ebpf_only("BPF.pid_tgid")
  end

  # ktime_ns is the monotonic clock in ns (u64 — the eBPF side only copies it to a u64 member or map, or applies `& M` / `>> K`).
  def self.ktime_ns
    BPF.ebpf_only("BPF.ktime_ns")
  end

  # Declares the widths of a record's members (`BPF.record(S, m: :u16, …)` — S is a Struct). Read by the frontend; does nothing at run time.
  def self.record(klass, fields)
    fields.length
  end

  # A record lookup result (only when present — inside `if p`). `p.load.m` / `p.load.m = e` read and write a member,
  # `p.atomic_add(:m, d)` atomically adds to a member. The result of p.load is usable only for direct member reads and writes.
  class RecordRef
    def initialize(value)
      @value = value
    end

    def load
      BPF.ebpf_only("BPF::RecordRef#load")
      @value
    end

    def atomic_add(member, a, b = 0) # (:m, d), or (:m, k, d) for an array member
      BPF.ebpf_only("BPF::RecordRef#atomic_add")
    end
  end

  # An array map with record values. sample is a sample of the record type (every member the literal 0 — not an initial value; the kernel creates entries as 0).
  class RecordMap
    def initialize(name, sample, max_entries)
      @name = name
      @sample = sample
      @max_entries = max_entries
    end

    def name
      @name
    end

    def sample
      @sample
    end

    # value_type is the declared spelling (`record:<S>` — as in maps.json).
    def value_type
      "record:" + @sample.class.name
    end

    def record?
      true
    end

    # kind and key_type are spelled as in maps.json (the declaration JSON of the user-space library).
    def kind
      "array"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end


    def max_entries
      @max_entries
    end

    def update(key, value)
      BPF.ebpf_only("BPF::RecordMap#update")
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::RecordMap#lookup") == 0
        return RecordRef.new(@sample)
      end
      nil
    end
  end

  # A ring buffer of record events. sample is a sample of the record type (every member the literal 0); size is in bytes (a power of 2, at least 4096).
  # output is true when a reservation was taken and submitted, false when the ring is full — accept it only as an `if` / `unless` condition or with `_ = …` (a statement that drops it is SB025).
  # `_ = Events.output(e)` chooses not to count dropped events (to count them, use the arm of `unless Events.output(e)`).
  class RingBuf
    def initialize(name, sample, size)
      @name = name
      @sample = sample
      @size = size
    end

    def name
      @name
    end

    def sample
      @sample
    end

    def size
      @size
    end

    def output(value)
      BPF.ebpf_only("BPF::RingBuf#output") == 0
    end

    # output_str writes value (S.new(…)) into the reservation, reads the user string str (ctx.str_arg(n)) into field (a u8 array member), also writes the status
    # to status_field (an :i64 member) and submits (uprobe only). nil when no reservation could be taken (nothing is read).
    def output_str(value, field, str, status_field)
      if BPF.ebpf_only("BPF::RingBuf#output_str") == 0
        return OutputStr.new
      end
      nil
    end

    # output_str_or_discard has the same shape as output_str, and discards the reservation when read_str's status < 0 (a failure such as NULL) (the event is not delivered —
    # bpf-mlir v1.3.0's per-arm submit / discard). An empty string is not discarded (its status differs by kernel — 1 on 7.1.8). The result is truthy only when a reservation was taken,
    # `r.sent` is true only when submitted (false when discarded), `r.status` is read_str's status.
    def output_str_or_discard(value, field, str, status_field)
      if BPF.ebpf_only("BPF::RingBuf#output_str_or_discard") == 0
        return OutputStr.new
      end
      nil
    end

    # output_comm writes value (S.new(…)) into the reservation, the current task's comm (bpf_get_current_comm) into field (a [:u8, 16] member),
    # and the helper's raw status into status_field (an :i64 member), then submits. nil when no reservation could be taken
    # output_argv, for each argv slot 0..19 (stopping at the first slot whose present is false), writes value into a reservation, the slot's string into field,
    # read_str's status into status_field and the slot number into index_field, then submits. 20 events do not tell "exactly 20" from "21 or more"
    def output_argv(value, field, argv, status_field, index_field)
      BPF.ebpf_only("BPF::RingBuf#output_argv")
    end

    # output_buf writes value into the reservation, n = max(0, min(len, N)) bytes of the user buffer (ctx.buf_arg(n)) into field (a [:u8, N]
    # member, zeroed as a whole first), probe_read_user's raw status into status_field (:i64), and n into count_field (:i32 — not the number of bytes
    # actually read), then submits (uprobe only). nil when no reservation could be taken
    def output_buf(value, field, buf, len, status_field, count_field)
      if BPF.ebpf_only("BPF::RingBuf#output_buf") == 0
        return OutputStr.new
      end
      nil
    end

    def output_comm(value, field, status_field)
      if BPF.ebpf_only("BPF::RingBuf#output_comm") == 0
        return OutputStr.new
      end
      nil
    end
  end

  # A hash map with integer values (value is :u32 / :u64 / :i32 / :i64 — lookup gives a MapRef). The key is :u32 / :u64 / :i32 / :i64 or a record sample.
  # update / insert / replace / delete return a status (0 or a negative errno — BPF::EEXIST etc.), accepted only as `st = M.op(…)` (read it), a comparison operand, or `_ = M.op(…)` (a statement that drops it is SB026).
  class HashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      @value.to_s
    end

    def record?
      false
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::HashMap#lookup") == 0
        return MapRef.new
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::HashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::HashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::HashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::HashMap#delete")
    end

    # add_or_init atomically adds delta to the value if the key exists, otherwise creates it with delta (a concurrent create adds after −EEXIST; absent again gives a synthesized −ENOENT). Returns a status.
    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::HashMap#add_or_init")
    end
  end

  # An lru_hash map with integer values (value is :u32 / :u64 / :i32 / :i64 — lookup gives a MapRef). The key is :u32 / :u64 / :i32 / :i64 or a record sample.
  # update / insert / replace / delete return a status (0 or a negative errno — BPF::EEXIST etc.), accepted only as `st = M.op(…)` (read it), a comparison operand, or `_ = M.op(…)` (a statement that drops it is SB026).
  class LruHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "lru_hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      @value.to_s
    end

    def record?
      false
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::LruHashMap#lookup") == 0
        return MapRef.new
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::LruHashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::LruHashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::LruHashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::LruHashMap#delete")
    end

    # add_or_init atomically adds delta to the value if the key exists, otherwise creates it with delta (a concurrent create adds after −EEXIST; absent again gives a synthesized −ENOENT). Returns a status.
    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::LruHashMap#add_or_init")
    end
  end

  # A hash map with record values (value is a record sample `S.new(0, …)` — lookup gives a RecordRef). The key is :u32 / :u64 / :i32 / :i64 or a record sample.
  # update / insert / replace / delete return a status (0 or a negative errno — BPF::EEXIST etc.), accepted only as `st = M.op(…)` (read it), a comparison operand, or `_ = M.op(…)` (a statement that drops it is SB026).
  class RecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      "record:" + @value.class.name
    end

    def record?
      true
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::RecordHashMap#lookup") == 0
        return RecordRef.new(@value)
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::RecordHashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::RecordHashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::RecordHashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::RecordHashMap#delete")
    end
  end

  # An lru_hash map with record values (value is a record sample `S.new(0, …)` — lookup gives a RecordRef). The key is :u32 / :u64 / :i32 / :i64 or a record sample.
  # update / insert / replace / delete return a status (0 or a negative errno — BPF::EEXIST etc.), accepted only as `st = M.op(…)` (read it), a comparison operand, or `_ = M.op(…)` (a statement that drops it is SB026).
  class LruRecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "lru_hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      "record:" + @value.class.name
    end

    def record?
      true
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::LruRecordHashMap#lookup") == 0
        return RecordRef.new(@value)
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::LruRecordHashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::LruRecordHashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::LruRecordHashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::LruRecordHashMap#delete")
    end
  end

  # A per-CPU percpu_array — the same shape as BPF::ArrayMap; eBPF-side reads and writes use the current CPU's slot. No two CPUs write the same slot at once, so
  # the form that writes a lookup's value back to the same entry (`p.load.m += d` etc.) is accepted (when every program using the map is XDP — tracing / perf programs can interrupt softirq).
  class PerCpuArrayMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
    end

    def name
      @name
    end

    def value_type
      @value_type.to_s # a String in every map class (a Symbol index goes wrong in the library's polymorphic arguments)
    end

    # record? lets the user-space library tell integer maps from record maps.
    def record?
      false
    end

    # kind and key_type are spelled as in maps.json (the declaration JSON of the user-space library).
    def kind
      "percpu_array"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end


    def max_entries
      @max_entries
    end

    def atomic_add(key, delta)
      BPF.ebpf_only("BPF::PerCpuArrayMap#atomic_add")
    end

    def update(key, value)
      BPF.ebpf_only("BPF::PerCpuArrayMap#update")
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::PerCpuArrayMap#lookup") == 0
        return MapRef.new
      end
      nil
    end
  end

  # A per-CPU percpu_array — the same shape as BPF::RecordMap; eBPF-side reads and writes use the current CPU's slot. No two CPUs write the same slot at once, so
  # the form that writes a lookup's value back to the same entry (`p.load.m += d` etc.) is accepted (when every program using the map is XDP — tracing / perf programs can interrupt softirq).
  class PerCpuRecordMap
    def initialize(name, sample, max_entries)
      @name = name
      @sample = sample
      @max_entries = max_entries
    end

    def name
      @name
    end

    def sample
      @sample
    end

    # value_type is the declared spelling (`record:<S>` — as in maps.json).
    def value_type
      "record:" + @sample.class.name
    end

    def record?
      true
    end

    # kind and key_type are spelled as in maps.json (the declaration JSON of the user-space library).
    def kind
      "percpu_array"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end


    def max_entries
      @max_entries
    end

    def update(key, value)
      BPF.ebpf_only("BPF::PerCpuRecordMap#update")
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::PerCpuRecordMap#lookup") == 0
        return RecordRef.new(@sample)
      end
      nil
    end
  end

  # A per-CPU percpu_hash — the same shape as BPF::HashMap; eBPF-side reads and writes use the current CPU's slot. No two CPUs write the same slot at once, so
  # the form that writes a lookup's value back to the same entry (`p.load.m += d` etc.) is accepted (when every program using the map is XDP — tracing / perf programs can interrupt softirq).
  class PerCpuHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "percpu_hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      @value.to_s
    end

    def record?
      false
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::PerCpuHashMap#lookup") == 0
        return MapRef.new
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::PerCpuHashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::PerCpuHashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::PerCpuHashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::PerCpuHashMap#delete")
    end

    # add_or_init atomically adds delta to the value if the key exists, otherwise creates it with delta (a concurrent create adds after −EEXIST; absent again gives a synthesized −ENOENT). Returns a status.
    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::PerCpuHashMap#add_or_init")
    end
  end

  # A per-CPU percpu_hash — the same shape as BPF::RecordHashMap; eBPF-side reads and writes use the current CPU's slot. No two CPUs write the same slot at once, so
  # the form that writes a lookup's value back to the same entry (`p.load.m += d` etc.) is accepted (when every program using the map is XDP — tracing / perf programs can interrupt softirq).
  class PerCpuRecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @key = key
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "percpu_hash"
    end

    # key_type / value_type are spelled as in maps.json (`u32` / `record:<S>`).
    def key_type
      if @key.is_a?(Symbol)
        return @key.to_s
      end
      "record:" + @key.class.name
    end

    def value_type
      "record:" + @value.class.name
    end

    def record?
      true
    end

    def record_key?
      !@key.is_a?(Symbol)
    end

    def max_entries
      @max_entries
    end

    def lookup(key)
      if BPF.ebpf_only("BPF::PerCpuRecordHashMap#lookup") == 0
        return RecordRef.new(@value)
      end
      nil
    end

    def update(key, value)
      BPF.ebpf_only("BPF::PerCpuRecordHashMap#update")
    end

    def insert(key, value)
      BPF.ebpf_only("BPF::PerCpuRecordHashMap#insert")
    end

    def replace(key, value)
      BPF.ebpf_only("BPF::PerCpuRecordHashMap#replace")
    end

    def delete(key)
      BPF.ebpf_only("BPF::PerCpuRecordHashMap#delete")
    end
  end

  # An lpm_trie map (IPv4 longest-prefix match) with integer values (value is :u32 / :i32 — lookup gives a MapRef). The library owns the key (spinelbpf_lpm_key4 with
  # prefixlen u32 and addr [4]u8 — the frontend creates it). The eBPF side has only `p = M.lookup(a0, a1, a2, a3)` (the 4 address bytes — looked up with prefixlen 32) and `p.load` inside `if p`
  # (read-only — writes go through obj.lpm_put on the user side).
  class LpmTrieMap
    def initialize(name, value, max_entries)
      @name = name
      @value = value
      @max_entries = max_entries
    end

    def name
      @name
    end

    def kind
      "lpm_trie"
    end

    # key_type / value_type are spelled as in maps.json.
    def key_type
      "record:spinelbpf_lpm_key4"
    end

    def value_type
      @value.to_s
    end

    def record?
      false
    end

    def record_key?
      true
    end

    def max_entries
      @max_entries
    end

    def lookup(a0, a1, a2, a3)
      if BPF.ebpf_only("BPF::LpmTrieMap#lookup") == 0
        return MapRef.new
      end
      nil
    end
  end

  # devmap: the target of XDP's redirect_map — the key is a u32 index, the value an ifindex (:u32 — the user side fills it with `obj.map_put`).
  # The eBPF side has only `Ports.redirect(k, BPF::XDP_PASS)` as the last expression of an xdp program (XDP_REDIRECT if the entry exists, otherwise the fallback).
  class DevMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
    end

    def name
      @name
    end

    def value_type
      @value_type.to_s
    end

    def record?
      false
    end

    def kind
      "devmap"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end

    def max_entries
      @max_entries
    end

    def redirect(key, fallback)
      BPF.ebpf_only("BPF::DevMap#redirect")
      fallback
    end
  end

  # sockmap: the source of sk_lookup's sk.assign — the key is a u32 index, the value a socket (the user side puts an fd with `obj.map_put` — :u64).
  # The eBPF side has only the sk_lookup program statement `st = Socks.assign(ctx, k)` (a socket reference never becomes a Ruby value).
  class SockMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
    end

    def name
      @name
    end

    def value_type
      @value_type.to_s
    end

    def record?
      false
    end

    def kind
      "sockmap"
    end

    def key_type
      "u32"
    end

    def record_key?
      false
    end

    def max_entries
      @max_entries
    end

    def assign(ctx, key)
      BPF.ebpf_only("BPF::SockMap#assign")
    end
  end

  # The sk_lookup context (bpf_sk_lookup). ctx.local_port is a u32 in host order (ebpf.ctx.field)
  class SkLookupCtx
    def local_port
      BPF.ebpf_only("BPF::SkLookupCtx#local_port")
    end
  end

  # Declares an sk_lookup program (`BPF.sk_lookup :name`). The user side attaches it to a netns with attach_netns; tests use test_run_sk_lookup.
  def self.sk_lookup(name)
    name
  end

  # Declares an xdp program (`BPF.xdp :name`). Read by the frontend; at run time it only returns the name.
  def self.xdp(name)
    name
  end

  # Declares a sched_cls program (`BPF.tcx :name, :ingress` / `:egress`; the direction is a Symbol literal, the tcx link's direction). Read by the frontend; at run time it only returns the name.
  def self.tcx(name, direction)
    name
  end

  # Declares a socket_filter program (`BPF.socket_filter :name`). The user side attaches it to its own socket with `obj.attach_socket(<name as a String>, fd)`. At run time it only returns the name.
  def self.socket_filter(name)
    name
  end

  # Declares a cgroup_skb program (`BPF.cgroup_skb :name, :ingress` / `:egress`). The user side attaches it to a cgroup with `obj.attach_cgroup(<name as a String>, cgroup_fd)`.
  # At run time it only returns the name.
  def self.cgroup_skb(name, direction)
    name
  end

  # Declares a netfilter program (`BPF.netfilter :name`). The user side's `obj.attach_netfilter(<name as a String>, pf, hooknum, priority)` attaches the hook
  # in the calling thread's netns. At run time it only returns the name.
  def self.netfilter(name)
    name
  end

  # Declares an fmod_ret program (`BPF.fmod_ret :name, "kernel_function", nargs: N, args: {0 => :i32}`). nargs is the target's argument count,
  # args the integer arguments (ctx.arg(i)); the return value is i32. Checked against the target's FUNC_PROTO before load (retsig, farg). At run time it only returns the name.
  def self.fmod_ret(name, target, opts)
    name
  end

  # Overrides the fmod_ret value: at the end of the program or in a guard `return … if cond`, skip the original function and return e
  def self.fmod_return(e)
    BPF.ebpf_only("BPF.fmod_return")
  end

  # Declares a flow_dissector program (`BPF.flow_dissector :name`). The user side uses `obj.attach_netns(<name as a String>, netns_fd)`. At run time it only returns the name.
  def self.flow_dissector(name)
    name
  end

  # Declares a CO-RE kernel struct (`BPF.kernel_type(Task, "task_struct", pid: :i32, real_parent: [:kptr, Task], comm: [:u8, 16])`).
  # Read by the frontend; does nothing at run time.
  def self.kernel_type(s, name, opts)
    name
  end

  # Declares a tp_btf program (`BPF.tp_btf :name, "sched_process_fork", args: {0 => TaskT, 1 => TaskT}`). Read by the frontend.
  def self.tp_btf(name, tracepoint, opts)
    name
  end

  # Declares a uprobe program (`BPF.uprobe :name, "target/bin", "symbol", params: {1 => :user_str, 2 => :i32}`). The path is relative to the source's
  # directory (the build reads it and puts the SHA-256 into the schema — the path does not go into the outputs). Read by the frontend; at run time it only returns the name.
  def self.uprobe(name, path, symbol, opts)
    name
  end

  #   BPF.uretprobe :name, "target/binary", "symbol", ret: :i64 — ctx.ret gives the return-value register
  def self.uretprobe(name, path, symbol, opts)
    name
  end

  # Declares tracing programs (read by the frontend; at run time it only returns the name). target is a String literal naming a kernel function.
  #   BPF.fentry :name, "target"                              — arguments cannot be read (v0.17.0 has no fentry integer arguments — helpers only)
  #   BPF.fexit :name, "target", nargs: N, ret: :i32          — ctx.ret gives the return value (N is the target's argument count)
  #   BPF.kprobe :name, "target", params: {3 => :u64}        — ctx.arg(n) gives register n as an integer (1-based — the same n as the schema's params)
  #   BPF.fentry :name, "target", args: {0 => [:or_null, T]} — struct arguments (ctx.kptr_or_null and if)
  def self.fentry(name, target, opts = nil)
    name
  end

  def self.fexit(name, target, opts)
    name
  end

  def self.kprobe(name, target, opts)
    name
  end

  #   BPF.kretprobe :name, "target", ret: :i32          — ctx.ret gives the return-value register
  def self.kretprobe(name, target, opts)
    name
  end

  #   BPF.raw_tp :name, "tracepoint"                    — ctx.arg(i) gives args[i] (u64)
  def self.raw_tp(name, target)
    name
  end

  #   BPF.tracepoint :name, "cat/event", fields: {f => [offset, :type]} — ctx.field(:f)
  def self.tracepoint(name, target, opts)
    name
  end

  #   BPF.ksyscall :name, "syscall", params: {n => :type} — ctx.arg(n) gives the syscall's n-th argument
  def self.ksyscall(name, target, opts)
    name
  end
end
