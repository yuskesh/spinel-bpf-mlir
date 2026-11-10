





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



  class XdpMd
    def initialize(bytes)
      @bytes = bytes
      @ifx = 1
    end

    def check(off, len)
      if off >= 0 && off + len <= @bytes.length
        return Window.new(@bytes, off)
      end
      nil
    end


    def ingress_ifindex
      @ifx
    end

    def _h_ifx(v)
      @ifx = v
      self
    end



    def adjust_head(d)
      lim = 14
      if BPF::ADJH_BOUND[0] != 0
        lim = BPF::ADJH_BOUND[0]
      end
      if d > 0
        if @bytes.length - d < lim
          return -22
        end
        @bytes = @bytes[d, @bytes.length - d]
      elsif d < 0
        if -d > 200
          return -22
        end
        @bytes = Array.new(-d, 0) + @bytes
      end
      0
    end



    def adjust_tail(k)
      lim = 14
      if BPF::ADJH_BOUND[0] != 0
        lim = BPF::ADJH_BOUND[0]
      end
      if @bytes.length + k < lim
        return -22
      end
      @bytes = @bytes[0, @bytes.length + k]
      0
    end
  end


  class SkBuff
    def initialize(bytes)
      @bytes = bytes
      @mark = 0
    end

    def check(off, len)
      if off >= 0 && off + len <= @bytes.length
        return Window.new(@bytes, off)
      end
      nil
    end


    def len
      @bytes.length
    end

    def mark
      @mark
    end

    def mark=(v)
      @mark = v
    end
  end



  class CgroupSkb
    def initialize(bytes, hdr)
      @bytes = bytes
      @hdr = hdr
    end

    def check(off, len)
      if off >= 0 && @hdr + off + len <= @bytes.length
        return Window.new(@bytes, @hdr + off)
      end
      nil
    end

    def len
      @bytes.length - @hdr
    end
  end


  class Window
    def initialize(bytes, off)
      @bytes = bytes
      @off = off
    end

    def u8(i)
      @bytes[@off + i]
    end

    def be16(i)
      (@bytes[@off + i] << 8) | @bytes[@off + i + 1]
    end

    def le16(i)
      @bytes[@off + i] | (@bytes[@off + i + 1] << 8)
    end

    def be32(i)
      (be16(i) << 16) | be16(i + 2)
    end

    def le32(i)
      le16(i) | (le16(i + 2) << 16)
    end
  end


  class MapRef
    def initialize(map, key)
      @map = map
      @key = key
    end

    def load
      @map.peek(@key)
    end

    def atomic_add(delta)
      @map.atomic_add(@key, delta)
    end
  end

  class ArrayMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
      @vals = Array.new(max_entries, 0)
    end

    def name
      @name
    end

    def value_type
      @value_type
    end

    def max_entries
      @max_entries
    end

    def in_range(key)
      key >= 0 && key < @max_entries
    end

    def wrap(v)
      if @value_type == :u32
        return v & 0xffffffff
      end
      if @value_type == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def reset
      i = 0
      while i < @max_entries
        @vals[i] = 0
        i += 1
      end
      0
    end


    def poke(key, value)
      @vals[key] = value
    end

    def atomic_add(key, delta)
      if in_range(key)
        @vals[key] = wrap(@vals[key] + delta)
      end
      0
    end

    def update(key, value)
      if in_range(key)
        @vals[key] = wrap(value)
      end
      0
    end

    def lookup(key)
      if in_range(key)
        return MapRef.new(self, key)
      end
      nil
    end


    def peek(key)
      @vals[key]
    end
  end



  class DevMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
      @vals = Array.new(max_entries, 0)
    end

    def name
      @name
    end

    def value_type
      @value_type
    end

    def max_entries
      @max_entries
    end

    def reset
      i = 0
      while i < @max_entries
        @vals[i] = 0
        i += 1
      end
      0
    end

    def poke(key, value)
      @vals[key] = value & 0xffffffff
    end

    def peek(key)
      @vals[key]
    end

    def redirect(key, fallback)
      if key >= 0 && key < @max_entries && @vals[key] != 0
        return 4
      end
      fallback
    end
  end



  class SockMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
      @protos = Array.new(max_entries, 0)
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end

    def reset
      i = 0
      while i < @max_entries
        @protos[i] = 0
        i += 1
      end
      0
    end

    def poke(key, value)
      @protos[key] = value
    end

    def peek(key)
      @protos[key]
    end

    def assign(ctx, key)
      if key < 0 || key >= @max_entries || @protos[key] == 0
        return -2
      end
      if @protos[key] != ctx.protocol
        return -91
      end
      0
    end
  end


  class SkLookupCtx
    def initialize(protocol, local_port)
      @protocol = protocol
      @local_port = local_port
    end

    def protocol
      @protocol
    end

    def local_port
      @local_port
    end
  end



  def self.record(klass, fields)
    fields.length
  end




GLOBAL_NAMES = []
GLOBAL_VALUES = []

def self.set_global(name, v)
  i = 0
  while i < GLOBAL_NAMES.length
    if GLOBAL_NAMES[i] == name
      GLOBAL_VALUES[i] = v
      return v
    end
    i += 1
  end
  GLOBAL_NAMES.push(name)
  GLOBAL_VALUES.push(v)
  v
end

def self.global_read(name, required)
  i = 0
  while i < GLOBAL_NAMES.length
    if GLOBAL_NAMES[i] == name
      return GLOBAL_VALUES[i]
    end
    i += 1
  end
  if required
    raise "config #{name} is not set"
  end
  0
end

def self.global_add(name, type, d)
  v = global_read(name, false) + d
  if type == "u32"
    v = v & 0xFFFFFFFF
  elsif type == "i32"
    v = ((v & 0xFFFFFFFF) ^ 0x80000000) - 0x80000000
  end
  set_global(name, v)
end

class Config
  def initialize(name, type)
    @name = name
    @type = type.to_s
  end

  def value
    BPF.global_read(@name, true)
  end
end

class OptionalConfig
  def initialize(name, type)
    @name = name
    @type = type.to_s
  end

  def value
    BPF.global_read(@name, false)
  end
end

class Counter
  def initialize(name, type)
    @name = name
    @type = type.to_s
  end

  def value
    BPF.global_read(@name, false)
  end

  def add(d)
    BPF.global_add(@name, @type, d)
    0
  end
end

  def self.ktime_ns
    1
  end



  TASK = [0]

  def self.pid_tgid
    TASK[0]
  end


  TASK_COMM = Array.new(16, 0)

  def self.set_comm(s)
    b = s.bytes
    i = 0
    while i < 16
      if i < 15 && i < b.length
        TASK_COMM[i] = b[i]
      else
        TASK_COMM[i] = 0
      end
      i += 1
    end
    0
  end


  class FentryCtx
    def initialize(kptrs = nil, idx = nil, ints = nil)
      @kptrs = kptrs
      @idx = idx
      @ints = ints
    end


    def arg(i)
      @ints[i]
    end

    def kptr_or_null(i, t)
      j = 0
      while j < @idx.length
        if @idx[j] == i
          return @kptrs[j]
        end
        j += 1
      end
      raise "twin: argument #{i} is not a declared struct argument"
    end
  end

  class FexitCtx
    def initialize(ret)
      @ret = ret
    end

    def ret
      @ret
    end
  end


  class FmodRetCtx
    def initialize(ints)
      @ints = ints
    end

    def arg(i)
      @ints[i]
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
      @names = []
      @ptrs = []
      @anames = []
      @arrs = []
      @snames = []
      @strs = []
      @addr = 0
    end


    def set_addr(a)
      @addr = a
    end

    def addr
      @addr
    end


    def set_arr(field, a)
      @anames.push(field)
      @arrs.push(a)
    end

    def copy(field)
      j = 0
      while j < @anames.length
        if @anames[j] == field
          out = Array.new(0, 0)
          k = 0
          while k < @arrs[j].length
            out.push(@arrs[j][k])
            k += 1
          end
          return out
        end
        j += 1
      end
      raise "twin: no array member #{field}"
    end


    def set_str(field, a)
      @snames.push(field)
      @strs.push(a)
    end

    def str(field)
      j = 0
      while j < @snames.length
        if @snames[j] == field
          return UserStr.new(@strs[j], false)
        end
        j += 1
      end
      UserStr.new(Array.new(0, 0), false)
    end

    def load
      @value
    end

    def set_ptr(field, kp)
      @names.push(field)
      @ptrs.push(kp)
    end

    def ptr(field, t)
      j = 0
      while j < @names.length
        if @names[j] == field
          return @ptrs[j]
        end
        j += 1
      end
      nil
    end
  end





  class FlowCtx
    def initialize(bytes)
      @bytes = bytes
      @k = Array.new(56, 0)
      if bytes.length >= 14
        @k[10] = bytes[12]
        @k[11] = bytes[13]
      end
      _h_put(0, 2, 14)
      _h_put(2, 2, 14)
    end

    def check(off, len)
      if off >= 0 && off + len <= @bytes.length
        return Window.new(@bytes, off)
      end
      nil
    end


    def _h_off(f)
      if f == :nhoff
        return 0
      elsif f == :thoff
        return 2
      elsif f == :addr_proto
        return 4
      elsif f == :is_frag
        return 6
      elsif f == :is_first_frag
        return 7
      elsif f == :is_encap
        return 8
      elsif f == :ip_proto
        return 9
      elsif f == :n_proto
        return 10
      elsif f == :sport
        return 12
      elsif f == :dport
        return 14
      elsif f == :ipv4_src || f == :ipv6_src
        return 16
      elsif f == :ipv4_dst
        return 20
      elsif f == :ipv6_dst
        return 32
      elsif f == :flags
        return 48
      end
      52
    end

    def _h_width(f)
      if f == :is_frag || f == :is_first_frag || f == :is_encap || f == :ip_proto
        return 1
      elsif f == :ipv4_src || f == :ipv4_dst || f == :ipv6_src || f == :ipv6_dst || f == :flags || f == :flow_label
        return 4
      end
      2
    end

    def _h_get(off, w)
      v = 0
      i = w - 1
      while i >= 0
        v = (v << 8) | @k[off + i]
        i -= 1
      end
      v
    end

    def _h_put(off, w, v)
      i = 0
      while i < w
        @k[off + i] = (v >> (8 * i)) & 0xFF
        i += 1
      end
    end

    def key(f, i = 0)
      _h_get(_h_off(f) + 4 * i, _h_width(f))
    end


    def set_key(f, a, b = 0)
      if f == :ipv6_src || f == :ipv6_dst
        _h_put(_h_off(f) + 4 * a, 4, b)
      else
        _h_put(_h_off(f), _h_width(f), a)
      end
      nil
    end


    def _h_keys(cl)
      n = @bytes.length
      nh = _h_get(0, 2)
      if nh < 14
        nh = 14
      elsif nh > n
        nh = n
      end
      th = _h_get(2, 2)
      if cl != 0
        if th < nh
          th = nh
        elsif th > n
          th = n
        end
      end
      [nh, th, _h_get(4, 2), _h_get(6, 1), _h_get(7, 1), _h_get(8, 1), _h_get(9, 1), _h_get(10, 2), _h_get(12, 2), _h_get(14, 2),
       _h_get(16, 4), _h_get(20, 4), _h_get(24, 4), _h_get(28, 4), _h_get(32, 4), _h_get(36, 4), _h_get(40, 4), _h_get(44, 4),
       _h_get(48, 4), _h_get(52, 4)]
    end
  end


  class NfCtx
    def initialize(state, skb)
      @state = state
      @skb = skb
    end

    def state(t)
      @state
    end

    def skb(t)
      @skb
    end
  end

  class TpBtfCtx
    def initialize(kptrs, idx, ints)
      @kptrs = kptrs
      @idx = idx
      @ints = ints
    end

    def kptr(i, t)
      j = 0
      while j < @idx.length
        if @idx[j] == i
          return @kptrs[j]
        end
        j += 1
      end
      raise "twin: argument #{i} is not a declared struct argument"
    end


    def kptr_or_null(i, t)
      j = 0
      while j < @idx.length
        if @idx[j] == i
          return @kptrs[j]
        end
        j += 1
      end
      raise "twin: argument #{i} is not a declared struct argument"
    end

    def arg(i)
      @ints[i]
    end
  end



  class UprobeCtx
    def initialize(args, strs, bufs)
      @args = args
      @strs = strs
      @bufs = bufs
    end

    def buf_arg(n)
      @bufs[n]
    end

    def arg(n)
      @args[n]
    end

    def str_arg(n)
      @strs[n]
    end
  end


  class UserStr
    def initialize(bytes, null)
      @bytes = bytes
      @null = null
    end

    def bytes
      @bytes
    end

    def null?
      @null
    end
  end


  class UserBuf
    def initialize(bytes, null)
      @bytes = bytes
      @null = null
    end

    def bytes
      @bytes
    end

    def null?
      @null
    end
  end


  class UserStrArray
    def initialize(items)
      @items = items
    end

    def items
      @items
    end
  end

  class OutputStr
    def initialize(status, sent)
      @status = status
      @sent = sent
    end

    def status
      @status
    end

    def sent
      @sent
    end
  end


  USTR_NULL_STATUS = [-14]


  ADJH_BOUND = [0]


  class UretprobeCtx
    def initialize(ret)
      @ret = ret
    end

    def ret
      @ret
    end
  end


  class KsyscallCtx
    def initialize(args, strs, arrs)
      @args = args
      @strs = strs
      @arrs = arrs
    end

    def arg(n)
      @args[n]
    end


    def str_arg(n)
      @strs[n]
    end


    def argv_arg(n)
      @arrs[n]
    end
  end


  class TracepointCtx
    def initialize(fields, strs, arrs, bytes)
      @fields = fields
      @strs = strs
      @arrs = arrs
      @bytes = bytes
    end


    def copy(name)
      @bytes[name.to_s]
    end

    def field(name)
      @fields[name.to_s]
    end


    def str_field(name)
      @strs[name.to_s]
    end


    def argv_field(name)
      @arrs[name.to_s]
    end
  end


  class RawTpCtx
    def initialize(args)
      @args = args
    end

    def arg(i)
      @args[i]
    end
  end


  class KretprobeCtx
    def initialize(ret)
      @ret = ret
    end

    def ret
      @ret
    end
  end



  class SocketFilterCtx
    def initialize(n, hdr)
      @len = n - hdr
    end

    def len
      @len
    end
  end

  class KprobeCtx

    def initialize(args, reads)
      @args = args
      @reads = reads
    end
  
    def arg(n)
      @args[n]
    end
  
    def read(n, offset, type)
      k = "#{n}_#{offset}"
      if @reads.key?(k)
        @reads[k]
      else
        [0, 0]
      end
    end
  end

  class RecordRef
    def initialize(name, slot)
      @name = name
      @slot = slot
    end

    def load
      _h_view(@name, @slot)
    end

    def atomic_add(member, a, b = 0)
      _h_radd(@name, @slot, member, a, b)
    end
  end

  class RecordMap
    def initialize(name, sample, max_entries)
      @name = name
      @sample = _h_flat(name, sample)
      @max_entries = max_entries
      @slots = []
      i = 0
      while i < max_entries
        @slots.push(_h_flat(name, sample))
        i += 1
      end
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end

    def in_range(key)
      key >= 0 && key < @max_entries
    end


    def update(key, value)
      if in_range(key)
        src = value.to_a
        i = 0
        while i < src.length
          @slots[key][i] = src[i]
          i += 1
        end
      end
      0
    end

    def lookup(key)
      if in_range(key)
        return RecordRef.new(@name, @slots[key])
      end
      nil
    end


    def slot(key)
      @slots[key]
    end

    def reset
      k = 0
      while k < @max_entries
        i = 0
        while i < @slots[k].length
          @slots[k][i] = 0
          i += 1
        end
        k += 1
      end
      0
    end
  end




  class RingBuf
    def initialize(name, sample, size)
      @name = name
      @size = size
      @events = []
      @used = 0
      @reserve = 0
      @limit = 0
    end

    def name
      @name
    end

    def _h_set(rec_bytes, limit)
      @reserve = (8 + rec_bytes + 7) / 8 * 8
      @limit = limit
      0
    end

    def output(value)
      if @reserve == 0
        raise "BPF::RingBuf #{@name}: the twin has no record size (the harness sets it)"
      end
      if @used + @reserve > @limit
        return false
      end
      @used += @reserve
      @events.push(value.to_a)
      true
    end




    def output_str(value, field, str, status_field)
      if @reserve == 0
        raise "BPF::RingBuf #{@name}: the twin has no record size (the harness sets it)"
      end
      if @used + @reserve > @limit
        return nil
      end
      @used += @reserve
      a = value.to_a
      buf = a[value.members.index(field)]
      st = USTR_NULL_STATUS[0]
      if !str.null?
        b = str.bytes
        n = b.length
        if n > buf.length - 1
          n = buf.length - 1
        end
        i = 0
        while i < n
          buf[i] = b[i]
          i += 1
        end
        buf[n] = 0
        st = n + 1
      end
      a[value.members.index(status_field)] = st
      @events.push(a)
      OutputStr.new(st, true)
    end



    def output_buf(value, field, buf, len, status_field, count_field)
      if @reserve == 0
        raise "BPF::RingBuf #{@name}: the twin has no record size (the harness sets it)"
      end
      if @used + @reserve > @limit
        return nil
      end
      @used += @reserve
      a = value.to_a
      fi = value.members.index(field)
      dst = Array.new(a[fi].length, 0)
      n = len
      if n > dst.length
        n = dst.length
      end
      if n < 0
        n = 0
      end
      st = 0
      if buf.null? && n > 0
        st = USTR_NULL_STATUS[0]
      elsif !buf.null?
        b = buf.bytes
        i = 0
        while i < n && i < b.length
          dst[i] = b[i]
          i += 1
        end
      end
      a[fi] = dst
      a[value.members.index(status_field)] = st
      a[value.members.index(count_field)] = n
      @events.push(a)
      OutputStr.new(st, true)
    end



    def output_argv(value, field, argv, status_field, index_field)
      if @reserve == 0
        raise "BPF::RingBuf #{@name}: the twin has no record size (the harness sets it)"
      end
      fi = value.members.index(field)
      si = value.members.index(status_field)
      xi = value.members.index(index_field)
      its = argv.items
      k = 0
      while k < 20 && k < its.length
        if @used + @reserve <= @limit
          @used += @reserve
          a = value.to_a
          src = a[fi]
          buf = Array.new(src.length, 0)
          b = its[k].bytes
          n = b.length
          if n > buf.length - 1
            n = buf.length - 1
          end
          i = 0
          while i < n
            buf[i] = b[i]
            i += 1
          end
          a[fi] = buf
          a[si] = n + 1
          a[xi] = k
          @events.push(a)
        end
        k += 1
      end
      0
    end


    def output_comm(value, field, status_field)
      if @reserve == 0
        raise "BPF::RingBuf #{@name}: the twin has no record size (the harness sets it)"
      end
      if @used + @reserve > @limit
        return nil
      end
      @used += @reserve
      a = value.to_a
      buf = a[value.members.index(field)]
      i = 0
      while i < 16
        buf[i] = TASK_COMM[i]
        i += 1
      end
      a[value.members.index(status_field)] = 0
      @events.push(a)
      OutputStr.new(0, true)
    end


    def output_str_or_discard(value, field, str, status_field)
      r = output_str(value, field, str, status_field)
      if r.nil?
        return nil
      end
      if r.status < 0
        @events.pop
        @used -= @reserve
        return OutputStr.new(r.status, false)
      end
      r
    end

    def drain
      out = @events
      @events = []
      @used = 0
      out
    end
  end


  class HashRef
    def initialize(map, key)
      @map = map
      @key = key
    end

    def load
      @map.peek(@key)
    end

    def atomic_add(delta)
      @map.atomic_add(@key, delta)
    end
  end


  class LruHashRef
    def initialize(map, key)
      @map = map
      @key = key
    end

    def load
      @map.peek(@key)
    end

    def atomic_add(delta)
      @map.atomic_add(@key, delta)
    end
  end



  class HashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = value
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => 0}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          return -7
        end
        @order.push(s)
      end
      @vals[s] = wrap(value)
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def add_or_init(key, delta)
      s = kstr(key)
      if @vals.key?(s)
        @vals[s] = wrap(@vals[s] + delta)
        return 0
      end
      write(key, delta, 1)
    end


    def peek(s)
      @vals[s]
    end

    def atomic_add(s, delta)
      @vals[s] = wrap(@vals[s] + delta)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return HashRef.new(self, s)
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      [@vals[s]]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end



  class LruHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = value
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => 0}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          victim = @order.shift
          @vals.delete(victim)
        end
        @order.push(s)
      end
      @vals[s] = wrap(value)
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def add_or_init(key, delta)
      s = kstr(key)
      if @vals.key?(s)
        @vals[s] = wrap(@vals[s] + delta)
        return 0
      end
      write(key, delta, 1)
    end


    def peek(s)
      @vals[s]
    end

    def atomic_add(s, delta)
      @vals[s] = wrap(@vals[s] + delta)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return LruHashRef.new(self, s)
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      [@vals[s]]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end



  class RecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = :u64
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => [0]}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          return -7
        end
        @order.push(s)
      end
      @vals[s] = value.to_a.dup
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return RecordRef.new(@name, @vals[s])
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      @vals[s]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end



  class LruRecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = :u64
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => [0]}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          victim = @order.shift
          @vals.delete(victim)
        end
        @order.push(s)
      end
      @vals[s] = value.to_a.dup
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return RecordRef.new(@name, @vals[s])
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      @vals[s]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end


  class PerCpuMapRef
    def initialize(map, key)
      @map = map
      @key = key
    end

    def load
      @map.peek(@key)
    end

    def atomic_add(delta)
      @map.atomic_add(@key, delta)
    end
  end


  class PerCpuHashRef
    def initialize(map, key)
      @map = map
      @key = key
    end

    def load
      @map.peek(@key)
    end

    def atomic_add(delta)
      @map.atomic_add(@key, delta)
    end
  end


  class PerCpuArrayMap
    def initialize(name, value_type, max_entries)
      @name = name
      @value_type = value_type
      @max_entries = max_entries
      @vals = Array.new(max_entries, 0)
    end

    def name
      @name
    end

    def value_type
      @value_type
    end

    def max_entries
      @max_entries
    end

    def in_range(key)
      key >= 0 && key < @max_entries
    end

    def wrap(v)
      if @value_type == :u32
        return v & 0xffffffff
      end
      if @value_type == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def reset
      i = 0
      while i < @max_entries
        @vals[i] = 0
        i += 1
      end
      0
    end


    def poke(key, value)
      @vals[key] = value
    end

    def atomic_add(key, delta)
      if in_range(key)
        @vals[key] = wrap(@vals[key] + delta)
      end
      0
    end

    def update(key, value)
      if in_range(key)
        @vals[key] = wrap(value)
      end
      0
    end

    def lookup(key)
      if in_range(key)
        return PerCpuMapRef.new(self, key)
      end
      nil
    end


    def peek(key)
      @vals[key]
    end
  end


  class PerCpuRecordMap
    def initialize(name, sample, max_entries)
      @name = name
      @sample = _h_flat(name, sample)
      @max_entries = max_entries
      @slots = []
      i = 0
      while i < max_entries
        @slots.push(_h_flat(name, sample))
        i += 1
      end
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end

    def in_range(key)
      key >= 0 && key < @max_entries
    end


    def update(key, value)
      if in_range(key)
        src = value.to_a
        i = 0
        while i < src.length
          @slots[key][i] = src[i]
          i += 1
        end
      end
      0
    end

    def lookup(key)
      if in_range(key)
        return RecordRef.new(@name, @slots[key])
      end
      nil
    end


    def slot(key)
      @slots[key]
    end

    def reset
      k = 0
      while k < @max_entries
        i = 0
        while i < @slots[k].length
          @slots[k][i] = 0
          i += 1
        end
        k += 1
      end
      0
    end
  end


  class PerCpuHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = value
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => 0}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          return -7
        end
        @order.push(s)
      end
      @vals[s] = wrap(value)
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def add_or_init(key, delta)
      s = kstr(key)
      if @vals.key?(s)
        @vals[s] = wrap(@vals[s] + delta)
        return 0
      end
      write(key, delta, 1)
    end


    def peek(s)
      @vals[s]
    end

    def atomic_add(s, delta)
      @vals[s] = wrap(@vals[s] + delta)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return PerCpuHashRef.new(self, s)
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      [@vals[s]]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end


  class PerCpuRecordHashMap
    def initialize(name, key, value, max_entries)
      @name = name
      @rk = !key.is_a?(Symbol)
      @vt = :u64
      @max_entries = max_entries
      @cap = max_entries
      @vals = {"" => [0]}
      @vals.delete("")
      @order = [""]
      @order.pop
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end


    def _h_cap(n)
      @cap = n
      0
    end

    def kstr(key)
      if @rk
        return key.to_a.join(",")
      end
      key.to_s
    end

    def wrap(v)
      if @vt == :u32
        return v & 0xffffffff
      end
      if @vt == :i32
        u = v & 0xffffffff
        if u >= 0x80000000
          return u - 0x100000000
        end
        return u
      end
      v
    end


    def write(key, value, flag)
      s = kstr(key)
      has = @vals.key?(s)
      if flag == 1 && has
        return -17
      end
      if flag == 2 && !has
        return -2
      end
      if !has
        if @vals.length >= @cap
          return -7
        end
        @order.push(s)
      end
      @vals[s] = value.to_a.dup
      0
    end

    def update(key, value)
      write(key, value, 0)
    end

    def insert(key, value)
      write(key, value, 1)
    end

    def replace(key, value)
      write(key, value, 2)
    end

    def delete(key)
      s = kstr(key)
      if !@vals.key?(s)
        return -2
      end
      @vals.delete(s)
      @order.delete(s)
      0
    end

    def lookup(key)
      s = kstr(key)
      if @vals.key?(s)
        return RecordRef.new(@name, @vals[s])
      end
      nil
    end


    def _h_keys
      @order.dup
    end

    def _h_val(s)
      @vals[s]
    end

    def reset
      @vals.clear
      @order.clear
      0
    end
  end


  class LpmRef
    def initialize(map, i)
      @map = map
      @i = i
    end

    def load
      @map.peek(@i)
    end
  end




  class LpmTrieMap
    def initialize(name, value, max_entries)
      @name = name
      @vt = value
      @max_entries = max_entries
      @plens = [0]
      @plens.pop
      @addrs = [0]
      @addrs.pop
      @vals = [0]
      @vals.pop
      @shortest = false
      @full_over = false
    end

    def name
      @name
    end

    def max_entries
      @max_entries
    end

    def wrap(v)
      u = v & 0xffffffff
      if @vt == :i32 && u >= 0x80000000
        return u - 0x100000000
      end
      u
    end


    def _h_shortest
      @shortest = true
      0
    end

    def _h_full_overwrite
      @full_over = true
      0
    end

    def mask(plen)
      if plen == 0
        return 0
      end
      (0xffffffff << (32 - plen)) & 0xffffffff
    end


    def lpm_best(x)
      best = -1
      i = 0
      while i < @plens.length
        if (x & mask(@plens[i])) == @addrs[i]
          if best < 0 || (!@shortest && @plens[i] > @plens[best]) || (@shortest && @plens[i] < @plens[best])
            best = i
          end
        end
        i += 1
      end
      best
    end

    def lookup(a0, a1, a2, a3)
      i = lpm_best((a0 << 24) | (a1 << 16) | (a2 << 8) | a3)
      if i >= 0
        return LpmRef.new(self, i)
      end
      nil
    end

    def peek(i)
      @vals[i]
    end


    def _h_addr(s)
      p = s.split(".")
      (p[0].to_i << 24) | (p[1].to_i << 16) | (p[2].to_i << 8) | p[3].to_i
    end

    def _h_exact(plen, a)
      i = 0
      while i < @plens.length
        if @plens[i] == plen && @addrs[i] == a
          return i
        end
        i += 1
      end
      -1
    end


    def _h_put(prefix, v)
      f = prefix.split("/")
      plen = f[1].to_i
      a = _h_addr(f[0])
      i = _h_exact(plen, a)
      if i >= 0 && @full_over && @plens.length >= @max_entries
        return -28
      end
      if i >= 0
        @vals[i] = wrap(v)
        return 0
      end
      if @plens.length >= @max_entries
        return -28
      end
      @plens.push(plen)
      @addrs.push(a)
      @vals.push(wrap(v))
      0
    end

    def _h_remove(prefix)
      f = prefix.split("/")
      i = _h_exact(f[1].to_i, _h_addr(f[0]))
      if i < 0
        return -2
      end
      @plens.delete_at(i)
      @addrs.delete_at(i)
      @vals.delete_at(i)
      0
    end


    def _h_match(s)
      i = lpm_best(_h_addr(s))
      if i < 0
        return "absent"
      end
      @vals[i].to_s
    end

    def _h_ip(a)
      "#{(a >> 24) & 255}.#{(a >> 16) & 255}.#{(a >> 8) & 255}.#{a & 255}"
    end


    def _h_list
      out = [""]
      out.pop
      i = 0
      while i < @plens.length
        out.push("#{_h_ip(@addrs[i])}/#{@plens[i]} #{@vals[i]}")
        i += 1
      end
      out
    end

    def reset
      @plens.clear
      @addrs.clear
      @vals.clear
      0
    end
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

  def self.xdp(name)
    name
  end

  def self.tcx(name, direction)
    name
  end

  def self.flow_dissector(name)
    name
  end

  def self.sk_lookup(name)
    name
  end

  def self.netfilter(name)
    name
  end

  def self.fmod_ret(name, target, opts)
    name
  end


  def self.fmod_return(e)
    e
  end

  def self.cgroup_skb(name, direction)
    name
  end

  def self.socket_filter(name)
    name
  end

  def self.uprobe(name, path, symbol, opts)
    name
  end

  def self.uretprobe(name, path, symbol, opts)
    name
  end

  def self.kernel_type(s, name, opts)
    name
  end

  def self.tp_btf(name, tracepoint, opts)
    name
  end
end
