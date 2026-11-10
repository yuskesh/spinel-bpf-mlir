





module BPF
  XDP_ABORTED = 0
  XDP_DROP = 1
  XDP_PASS = 2
  XDP_TX = 3


  TC_PASS = 0
  TC_DROP = 2


  SF_KEEP = -1
  SF_DROP = 0


  CG_ALLOW = 1
  CG_DENY = 0


  NF_ACCEPT = 1
  NF_DROP = 0



  FMOD_CALL = 0


  FLOW_OK = 0
  FLOW_DROP = 2
  FLOW_CONTINUE = 129


  SK_PASS = 1
  SK_DROP = 0


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


  class XdpMd

    def check(off, len)
      if BPF.ebpf_only("BPF::XdpMd#check") == 0
        return Window.new
      end
      nil
    end


    def ingress_ifindex
      BPF.ebpf_only("BPF::XdpMd#ingress_ifindex")
    end



    def adjust_head(d)
      BPF.ebpf_only("BPF::XdpMd#adjust_head")
    end


    def adjust_tail(k)
      BPF.ebpf_only("BPF::XdpMd#adjust_tail")
    end
  end



  class SkBuff
    def check(off, len)
      if BPF.ebpf_only("BPF::SkBuff#check") == 0
        return Window.new
      end
      nil
    end


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






  class Config
    def initialize(name, type)
      @name = name
      @type = type.to_s
    end


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


  class FmodRetCtx
    def arg(i)
      BPF.ebpf_only("BPF::FmodRetCtx#arg")
    end
  end

  class KprobeCtx
    def arg(n)
      BPF.ebpf_only("BPF::KprobeCtx#arg")
    end


    def read(n, offset, type)
      z = BPF.ebpf_only("BPF::KprobeCtx#read")
      [z, z]
    end
  end


  class UretprobeCtx
    def ret
      BPF.ebpf_only("BPF::UretprobeCtx#ret")
    end
  end


  class KsyscallCtx
    def arg(n)
      BPF.ebpf_only("BPF::KsyscallCtx#arg")
    end


    def str_arg(n)
      if BPF.ebpf_only("BPF::KsyscallCtx#str_arg") == 0
        return UserStr.new
      end
      UserStr.new
    end


    def argv_arg(n)
      if BPF.ebpf_only("BPF::KsyscallCtx#argv_arg") == 0
        return UserStrArray.new
      end
      UserStrArray.new
    end
  end


  class TracepointCtx
    def field(name)
      BPF.ebpf_only("BPF::TracepointCtx#field")
    end


    def str_field(name)
      if BPF.ebpf_only("BPF::TracepointCtx#str_field") == 0
        return UserStr.new
      end
      UserStr.new
    end


    def argv_field(name)
      if BPF.ebpf_only("BPF::TracepointCtx#argv_field") == 0
        return UserStrArray.new
      end
      UserStrArray.new
    end


    def copy(name)
      BPF.ebpf_only("BPF::TracepointCtx#copy")
      Array.new(0, 0)
    end
  end


  class RawTpCtx
    def arg(i)
      BPF.ebpf_only("BPF::RawTpCtx#arg")
    end
  end


  class KretprobeCtx
    def ret
      BPF.ebpf_only("BPF::KretprobeCtx#ret")
    end
  end



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


  class SocketFilterCtx
    def len
      BPF.ebpf_only("BPF::SocketFilterCtx#len")
    end
  end



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


    def buf_arg(n)
      if BPF.ebpf_only("BPF::UprobeCtx#buf_arg") == 0
        return UserBuf.new
      end
      UserBuf.new
    end
  end



  class KernelType
    def initialize(sample)
      @sample = sample
    end

    def sample
      @sample
    end
  end



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



    def addr
      BPF.ebpf_only("BPF::KPtr#addr")
      0
    end


    def str(field)
      if BPF.ebpf_only("BPF::KPtr#str") == 0
        return UserStr.new
      end
      UserStr.new
    end
  end






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


  class UserStr
  end


  class UserStrArray
  end


  class UserBuf
  end




  class OutputStr
    def status
      BPF.ebpf_only("BPF::OutputStr#status")
    end


    def sent
      BPF.ebpf_only("BPF::OutputStr#sent") == 0
    end
  end



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


  class MapRef
    def load
      BPF.ebpf_only("BPF::MapRef#load")
    end


    def atomic_add(delta)
      BPF.ebpf_only("BPF::MapRef#atomic_add")
    end
  end


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
      @value_type.to_s
    end


    def record?
      false
    end


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


  def self.pid_tgid
    BPF.ebpf_only("BPF.pid_tgid")
  end


  def self.ktime_ns
    BPF.ebpf_only("BPF.ktime_ns")
  end


  def self.record(klass, fields)
    fields.length
  end



  class RecordRef
    def initialize(value)
      @value = value
    end

    def load
      BPF.ebpf_only("BPF::RecordRef#load")
      @value
    end

    def atomic_add(member, a, b = 0)
      BPF.ebpf_only("BPF::RecordRef#atomic_add")
    end
  end


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


    def value_type
      "record:" + @sample.class.name
    end

    def record?
      true
    end


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



    def output_str(value, field, str, status_field)
      if BPF.ebpf_only("BPF::RingBuf#output_str") == 0
        return OutputStr.new
      end
      nil
    end




    def output_str_or_discard(value, field, str, status_field)
      if BPF.ebpf_only("BPF::RingBuf#output_str_or_discard") == 0
        return OutputStr.new
      end
      nil
    end





    def output_argv(value, field, argv, status_field, index_field)
      BPF.ebpf_only("BPF::RingBuf#output_argv")
    end




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


    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::HashMap#add_or_init")
    end
  end



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


    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::LruHashMap#add_or_init")
    end
  end



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
      @value_type.to_s
    end


    def record?
      false
    end


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


    def value_type
      "record:" + @sample.class.name
    end

    def record?
      true
    end


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


    def add_or_init(key, delta)
      BPF.ebpf_only("BPF::PerCpuHashMap#add_or_init")
    end
  end



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


  class SkLookupCtx
    def local_port
      BPF.ebpf_only("BPF::SkLookupCtx#local_port")
    end
  end


  def self.sk_lookup(name)
    name
  end


  def self.xdp(name)
    name
  end


  def self.tcx(name, direction)
    name
  end


  def self.socket_filter(name)
    name
  end



  def self.cgroup_skb(name, direction)
    name
  end



  def self.netfilter(name)
    name
  end



  def self.fmod_ret(name, target, opts)
    name
  end


  def self.fmod_return(e)
    BPF.ebpf_only("BPF.fmod_return")
  end


  def self.flow_dissector(name)
    name
  end



  def self.kernel_type(s, name, opts)
    name
  end


  def self.tp_btf(name, tracepoint, opts)
    name
  end



  def self.uprobe(name, path, symbol, opts)
    name
  end


  def self.uretprobe(name, path, symbol, opts)
    name
  end






  def self.fentry(name, target, opts = nil)
    name
  end

  def self.fexit(name, target, opts)
    name
  end

  def self.kprobe(name, target, opts)
    name
  end


  def self.kretprobe(name, target, opts)
    name
  end


  def self.raw_tp(name, target)
    name
  end


  def self.tracepoint(name, target, opts)
    name
  end


  def self.ksyscall(name, target, opts)
    name
  end
end
