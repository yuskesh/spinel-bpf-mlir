














require "bpf"

module SpinelBPFC
  ffi_source <<~C
    extern const unsigned char spinelbpf_elf_start[] __attribute__((weak));
    extern const unsigned char spinelbpf_elf_end[] __attribute__((weak));
    extern const char spinelbpf_schema_sha[] __attribute__((weak));
    extern const char spinelbpf_maps_json[] __attribute__((weak));
    extern const char spinelbpf_records[] __attribute__((weak));
    void *spinelbpf_embedded_elf(void) { return (void *)spinelbpf_elf_start; }
    long spinelbpf_embedded_elf_len(void) { return spinelbpf_elf_start ? (long)(spinelbpf_elf_end - spinelbpf_elf_start) : 0; }
    const char *spinelbpf_embedded_sha(void) { return spinelbpf_schema_sha ? spinelbpf_schema_sha : ""; }
    const char *spinelbpf_embedded_maps(void) { return spinelbpf_maps_json ? spinelbpf_maps_json : ""; }
    const char *spinelbpf_embedded_records(void) { return spinelbpf_records ? spinelbpf_records : ""; }
    

    long spinelbpf_thread_current(void) { return (long)sp_Thread_current(); }
    long spinelbpf_thread_main(void) { return (long)sp_Thread_main(); }
    

    #include <string.h>
    long bml_attach_fentry(long obj, const char *prog, long prog_len);
    long bml_attach_fexit(long obj, const char *prog, long prog_len);
    long bml_attach_kprobe(long obj, const char *prog, long prog_len);
    long bml_attach_kretprobe(long obj, const char *prog, long prog_len);
    long bml_attach_tp_btf(long obj, const char *prog, long prog_len);
    long bml_test_run_tracing(long obj, const char *prog, long prog_len, long n);
    long bml_attach_raw_tp(long obj, const char *prog, long prog_len);
    long bml_attach_tracepoint(long obj, const char *prog, long prog_len, long flags);
    long bml_attach_ksyscall(long obj, const char *prog, long prog_len);
    long bml_test_run_ctx_inout(long obj, const char *prog, long prog_len, unsigned char *ctx_inout, long ctx_len);
    long bml_attach_fmod_ret(long obj, const char *prog, long prog_len);
    long spinelbpf_attach_trace(long obj, const char *prog, long kind) {
      long n = (long)strlen(prog);
      if (kind == 0) return bml_attach_fentry(obj, prog, n);
      if (kind == 8) return bml_attach_fmod_ret(obj, prog, n);
      if (kind == 1) return bml_attach_fexit(obj, prog, n);
      if (kind == 3) return bml_attach_tp_btf(obj, prog, n);
      if (kind == 4) return bml_attach_kretprobe(obj, prog, n);
      if (kind == 5) return bml_attach_raw_tp(obj, prog, n);
      if (kind == 7) return bml_attach_ksyscall(obj, prog, n);
      if (kind == 6) return bml_attach_tracepoint(obj, prog, n, 0);
      return bml_attach_kprobe(obj, prog, n);
    }
    long spinelbpf_run_tracing(long obj, const char *prog, long n) { return bml_test_run_tracing(obj, prog, (long)strlen(prog), n); }
    

    static unsigned long long spinelbpf_skl_cookie = 0;
    long spinelbpf_run_sk_lookup(long obj, const char *prog, long proto, long port) {
      unsigned char c[72];
      memset(c, 0, sizeof c);
      unsigned int fam = 2, pr = (unsigned int)proto, lp = (unsigned int)port;
      memcpy(c + 8, &fam, 4);
      memcpy(c + 12, &pr, 4);
      c[16] = 127; c[19] = 1;
      c[36] = 40000 >> 8; c[37] = 40000 & 255;
      c[40] = 127; c[43] = 1;
      memcpy(c + 60, &lp, 4);
      long r = bml_test_run_ctx_inout(obj, prog, (long)strlen(prog), c, (long)sizeof c);
      memcpy(&spinelbpf_skl_cookie, c, 8);
      return r;
    }
    long spinelbpf_sk_lookup_cookie(void) { return (long)spinelbpf_skl_cookie; }

    long spinelbpf_run_raw_tp(long obj, const char *prog, long *args, long n) {
      unsigned long long a[12] = {0};
      for (long i = 0; i < n && i < 12; i++) a[i] = (unsigned long long)args[i];
      return bml_test_run_ctx_inout(obj, prog, (long)strlen(prog), (unsigned char *)a, n * 8);
    }

    #include <stdlib.h>
    long bml_attach_tcx(long obj, const char *prog, long prog_len, const char *ifname, long if_len);
    long bml_link_tcx_direction(long link);
    long bml_test_run_tc_data(long obj, const char *prog, long prog_len, const unsigned char *data, long n);
    long spinelbpf_attach_tcx(long obj, const char *prog, const char *ifname) { return bml_attach_tcx(obj, prog, (long)strlen(prog), ifname, (long)strlen(ifname)); }
    long spinelbpf_tcx_direction(long link) { return bml_link_tcx_direction(link); }

    long bml_attach_socket(long obj, const char *prog, long prog_len, long sock_fd);
    long bml_test_run_skb_data(long obj, const char *prog, long prog_len, const unsigned char *data, long n);
    long spinelbpf_attach_socket(long obj, const char *prog, long fd) { return bml_attach_socket(obj, prog, (long)strlen(prog), fd); }
    long bml_attach_cgroup(long obj, const char *prog, long prog_len, long cgroup_fd);
    long spinelbpf_attach_cgroup(long obj, const char *prog, long fd) { return bml_attach_cgroup(obj, prog, (long)strlen(prog), fd); }
    long bml_attach_netfilter(long obj, const char *prog, long prog_len, long pf, long hooknum, long priority, long flags);
    long bml_test_run_netfilter(long obj, const char *prog, long prog_len, const unsigned char *data, long n, long pf, long hook);
    long spinelbpf_attach_netfilter(long obj, const char *prog, long pf, long hooknum, long priority) { return bml_attach_netfilter(obj, prog, (long)strlen(prog), pf, hooknum, priority, 0); }
    long bml_attach_netns(long obj, const char *prog, long prog_len, long netns_fd);
    long bml_test_run_flow_dissector(long obj, const char *prog, long prog_len, const unsigned char *data, long n, unsigned char *keys_out, long keys_cap);
    long spinelbpf_attach_netns(long obj, const char *prog, long fd) { return bml_attach_netns(obj, prog, (long)strlen(prog), fd); }
    static unsigned char spinelbpf_fk[56];
    long spinelbpf_run_flow(long obj, const char *prog, long *bytes, long n) {
      unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
      if (!b) abort();
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      memset(spinelbpf_fk, 0, sizeof spinelbpf_fk);
      long r = bml_test_run_flow_dissector(obj, prog, (long)strlen(prog), b, n, spinelbpf_fk, (long)sizeof spinelbpf_fk);
      free(b);
      return r;
    }

    long spinelbpf_flow_key(long i) {
      static const int off[20] = {0, 2, 4, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52};
      static const int wid[20] = {2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
      if (i < 0 || i >= 20) return -1;
      long v = 0;
      for (int k = wid[i] - 1; k >= 0; k--) v = (v << 8) | spinelbpf_fk[off[i] + k];
      return v;
    }

    long bml_load_checked_targets(const unsigned char *elf, long n, const char *sha, long sha_len, const char *maps, long maps_len, const char *config, long config_len, const char *targets, long targets_len, long caps_kind);
    long bml_attach_uprobe(long obj, const char *prog, long prog_len, long pid);
    long bml_attach_uretprobe(long obj, const char *prog, long prog_len, long pid);
    long bml_uprobe_link_file(long obj, long link);
    long spinelbpf_load_targets(void *elf, long n, const char *sha, const char *maps, const char *config, const char *targets, long caps) {
      return bml_load_checked_targets((const unsigned char *)elf, n, sha, (long)strlen(sha), maps, (long)strlen(maps), config, (long)strlen(config), targets, (long)strlen(targets), caps);
    }
    long spinelbpf_attach_uprobe(long obj, const char *prog, long pid) { return bml_attach_uprobe(obj, prog, (long)strlen(prog), pid); }
    long spinelbpf_attach_uretprobe(long obj, const char *prog, long pid) { return bml_attach_uretprobe(obj, prog, (long)strlen(prog), pid); }
    long spinelbpf_uprobe_link_file(long obj, long link) { return bml_uprobe_link_file(obj, link); }
    long spinelbpf_run_tc_packet(long obj, const char *prog, long *bytes, long n) {
      unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
      if (!b) abort();
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      long r = bml_test_run_tc_data(obj, prog, (long)strlen(prog), b, n);
      free(b);
      return r;
    }
    long spinelbpf_run_skb_packet(long obj, const char *prog, long *bytes, long n) {
      unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
      if (!b) abort();
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      long r = bml_test_run_skb_data(obj, prog, (long)strlen(prog), b, n);
      free(b);
      return r;
    }
    long spinelbpf_run_netfilter(long obj, const char *prog, long *bytes, long n, long pf, long hook) {
      unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
      if (!b) abort();
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      long r = bml_test_run_netfilter(obj, prog, (long)strlen(prog), b, n, pf, hook);
      free(b);
      return r;
    }

    long bml_load_checked_config(const unsigned char *elf, long n, const char *sha, long sha_len, const char *maps, long maps_len, const char *config, long config_len, long caps_kind);
    long bml_global_get(long obj, const char *decl, long decl_len);
    long spinelbpf_load_config(void *elf, long n, const char *sha, const char *maps, const char *config, long caps) {
      return bml_load_checked_config((const unsigned char *)elf, n, sha, (long)strlen(sha), maps, (long)strlen(maps), config, (long)strlen(config), caps);
    }
    long spinelbpf_global_get(long obj, const char *decl) { return bml_global_get(obj, decl, (long)strlen(decl)); }
    

    long bml_lpm_check_prefix(const char *prefix, long len);
    long bml_lpm_put(long obj, const char *decl, long decl_len, const char *prefix, long prefix_len, long bits);
    long bml_lpm_remove(long obj, const char *decl, long decl_len, const char *prefix, long prefix_len);
    long bml_lpm_match(long obj, const char *decl, long decl_len, const char *addr, long addr_len);
    long bml_lpm_list(long obj, const char *decl, long decl_len);
    long spinelbpf_lpm_prefix(const char *prefix) { return bml_lpm_check_prefix(prefix, (long)strlen(prefix)); }
    long spinelbpf_lpm_put(long obj, const char *decl, const char *prefix, long bits) { return bml_lpm_put(obj, decl, (long)strlen(decl), prefix, (long)strlen(prefix), bits); }
    long spinelbpf_lpm_remove(long obj, const char *decl, const char *prefix) { return bml_lpm_remove(obj, decl, (long)strlen(decl), prefix, (long)strlen(prefix)); }
    long spinelbpf_lpm_match(long obj, const char *decl, const char *addr) { return bml_lpm_match(obj, decl, (long)strlen(decl), addr, (long)strlen(addr)); }
    long spinelbpf_lpm_list(long obj, const char *decl) { return bml_lpm_list(obj, decl, (long)strlen(decl)); }
  C
  ffi_func :spinelbpf_embedded_elf, [], :ptr
  ffi_func :spinelbpf_embedded_elf_len, [], :long
  ffi_func :spinelbpf_embedded_sha, [], :str
  ffi_func :spinelbpf_embedded_maps, [], :str
  ffi_func :spinelbpf_embedded_records, [], :str
  ffi_func :spinelbpf_thread_current, [], :long
  ffi_func :spinelbpf_thread_main, [], :long
  ffi_func :spinelbpf_attach_trace, [:long, :str, :long], :long
  ffi_func :spinelbpf_run_tracing, [:long, :str, :long], :long
  ffi_func :spinelbpf_run_raw_tp, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_run_sk_lookup, [:long, :str, :long, :long], :long
  ffi_func :spinelbpf_sk_lookup_cookie, [], :long
  ffi_func :spinelbpf_attach_tcx, [:long, :str, :str], :long
  ffi_func :spinelbpf_tcx_direction, [:long], :long
  ffi_func :spinelbpf_load_targets, [:ptr, :long, :str, :str, :str, :str, :long], :long
  ffi_func :spinelbpf_attach_uprobe, [:long, :str, :long], :long
  ffi_func :spinelbpf_attach_uretprobe, [:long, :str, :long], :long
  ffi_func :spinelbpf_uprobe_link_file, [:long, :long], :long
  ffi_func :spinelbpf_run_tc_packet, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_attach_socket, [:long, :str, :long], :long
  ffi_func :spinelbpf_attach_cgroup, [:long, :str, :long], :long
  ffi_func :spinelbpf_attach_netfilter, [:long, :str, :long, :long, :long], :long
  ffi_func :spinelbpf_run_netfilter, [:long, :str, :int_array, :long, :long, :long], :long
  ffi_func :spinelbpf_attach_netns, [:long, :str, :long], :long
  ffi_func :spinelbpf_run_flow, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_flow_key, [:long], :long
  ffi_func :spinelbpf_run_skb_packet, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_load_config, [:ptr, :long, :str, :str, :str, :long], :long
  ffi_func :spinelbpf_global_get, [:long, :str], :long
  ffi_func :spinelbpf_lpm_prefix, [:str], :long
  ffi_func :spinelbpf_lpm_put, [:long, :str, :str, :long], :long
  ffi_func :spinelbpf_lpm_remove, [:long, :str, :str], :long
  ffi_func :spinelbpf_lpm_match, [:long, :str, :str], :long
  ffi_func :spinelbpf_lpm_list, [:long, :str], :long
  ffi_func :spinelbpf_load_checked, [:ptr, :long, :str, :str, :long], :long
  ffi_func :spinelbpf_attach_xdp, [:long, :str, :str], :long
  ffi_func :spinelbpf_detach, [:long], :long
  ffi_func :spinelbpf_map_get, [:long, :str, :long], :long
  ffi_func :spinelbpf_map_put, [:long, :str, :long, :long], :long
  ffi_func :spinelbpf_map_get_bytes, [:long, :str, :long, :int_array, :long], :long
  ffi_func :spinelbpf_map_put_bytes, [:long, :str, :long, :int_array, :long], :long
  ffi_func :spinelbpf_test_run_xdp, [:long, :str, :long], :long
  ffi_func :spinelbpf_test_run_xdp_packet, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_hash_get, [:long, :str, :int_array, :long, :int_array, :long], :long
  ffi_func :spinelbpf_hash_put, [:long, :str, :int_array, :long, :int_array, :long], :long
  ffi_func :spinelbpf_hash_delete, [:long, :str, :int_array, :long], :long
  ffi_func :spinelbpf_hash_keys, [:long, :str, :long, :int_array, :long], :long
  ffi_func :spinelbpf_possible_cpus, [], :long
  ffi_func :spinelbpf_percpu_get, [:long, :str, :int_array, :long, :int_array, :long], :long
  ffi_func :spinelbpf_percpu_put, [:long, :str, :int_array, :long, :int_array, :long], :long
  ffi_func :spinelbpf_ringbuf_open, [:long, :str], :long
  ffi_func :spinelbpf_ringbuf_read, [:long, :long, :int_array, :long], :long
  ffi_func :spinelbpf_ringbuf_close, [:long], :long
  ffi_func :spinelbpf_object_unmet, [:long], :long
  ffi_func :spinelbpf_close, [:long], :long
  ffi_func :spinelbpf_result_kind, [:long], :long
  ffi_func :spinelbpf_result_value, [:long], :long
  ffi_func :spinelbpf_result_message, [:long], :str
  ffi_func :spinelbpf_result_unmet_count, [:long], :long
  ffi_func :spinelbpf_result_unmet, [:long, :long], :str
  ffi_func :spinelbpf_result_free, [:long], :void
  ffi_func :spinelbpf_policy_version, [], :long
end

module SpinelBPF

  OK = 0
  KIND_NAMES = ["OK", "SCHEMA_MISMATCH", "PRECHECK_FAILED", "TARGET_REJECTED", "VERIFIER_REJECTED", "OTHER", "STATE", "RUNTIME_CONFLICT", "MAP_MISMATCH", "VALUE_RANGE", "CONFIG_NOT_SET", "NOT_FOUND"]



  FLOW_KEYS = ["nhoff", "thoff", "addr_proto", "is_frag", "is_first_frag", "is_encap", "ip_proto", "n_proto", "sport", "dport",
               "ipv6_src[0]", "ipv6_src[1]", "ipv6_src[2]", "ipv6_src[3]", "ipv6_dst[0]", "ipv6_dst[1]", "ipv6_dst[2]", "ipv6_dst[3]", "flags", "flow_label"]

  class Error < StandardError
  end
  class SchemaMismatch < Error
  end
  class PrecheckFailed < Error
  end
  class TargetRejected < Error
  end
  class VerifierRejected < Error
  end
  class Other < Error
  end
  class State < Error
  end

  class RuntimeConflict < Error
  end
  class MapMismatch < Error
  end
  class ValueRange < Error
  end

  class NotFound < Error
  end

  class ConfigNotSet < Error
  end


  def self.check(r)
    kind = SpinelBPFC.spinelbpf_result_kind(r)
    value = SpinelBPFC.spinelbpf_result_value(r)
    if kind == OK
      SpinelBPFC.spinelbpf_result_free(r)
      return value
    end
    msg = SpinelBPFC.spinelbpf_result_message(r)
    SpinelBPFC.spinelbpf_result_free(r)
    if kind == 1
      raise SchemaMismatch, msg
    elsif kind == 2
      raise PrecheckFailed, msg
    elsif kind == 3
      raise TargetRejected, msg
    elsif kind == 4

      if msg.include?("prohibited for !root") && !msg.include?("needs CAP_PERFMON")
        msg = msg + " — the verifier refused pointer arithmetic for a non-root loader: a packet window at a variable offset (`ctx.check(off, n)` with a non-constant off) needs CAP_PERFMON (or root) — bpf-mlir docs/nonroot.md"
      end
      raise VerifierRejected, msg
    elsif kind == 6
      raise State, msg
    elsif kind == 7
      raise RuntimeConflict, msg
    elsif kind == 8
      raise MapMismatch, msg
    elsif kind == 9
      raise ValueRange, msg
    elsif kind == 10
      raise ConfigNotSet, msg
    elsif kind == 11
      raise NotFound, msg
    end
    raise Other, msg
  end


  def self.current_thread
    SpinelBPFC.spinelbpf_thread_current
  end


  def self.main_thread?
    c = SpinelBPFC.spinelbpf_thread_current
    c == 0 || c == SpinelBPFC.spinelbpf_thread_main
  end



  def self.load_embedded
    load_embedded_config(ConfigSet.new)
  end


  def self.load_embedded_config(cfg)
    if !SpinelBPF.main_thread?
      raise State, "SpinelBPF.load_embedded: load from the main Thread only"
    end
    elf = SpinelBPFC.spinelbpf_embedded_elf
    n = SpinelBPFC.spinelbpf_embedded_elf_len
    if global_rows.length == 0
      if cfg.values_set > 0
        raise MapMismatch, "SpinelBPF.load_embedded_config: this program has no globals, but #{cfg.values_set} config values were given"
      end
      return Loaded.new(check(SpinelBPFC.spinelbpf_load_checked(elf, n, SpinelBPFC.spinelbpf_embedded_sha, SpinelBPFC.spinelbpf_embedded_maps, 0)))
    end
    Loaded.new(check(SpinelBPFC.spinelbpf_load_config(elf, n, SpinelBPFC.spinelbpf_embedded_sha, SpinelBPFC.spinelbpf_embedded_maps, cfg.json(optional_names), 0)))
  end




  def self.load_embedded_targets(cfg, targets)
    if !SpinelBPF.main_thread?
      raise State, "SpinelBPF.load_embedded_targets: load from the main Thread only"
    end
    elf = SpinelBPFC.spinelbpf_embedded_elf
    n = SpinelBPFC.spinelbpf_embedded_elf_len
    config = ""
    if global_rows.length == 0
      if cfg.values_set > 0
        raise MapMismatch, "SpinelBPF.load_embedded_targets: this program has no globals, but #{cfg.values_set} config values were given"
      end
    else
      config = cfg.json(optional_names)
    end
    Loaded.new(check(SpinelBPFC.spinelbpf_load_targets(elf, n, SpinelBPFC.spinelbpf_embedded_sha, SpinelBPFC.spinelbpf_embedded_maps, config, targets.json, 0)))
  end


  class UprobeTargets
    def initialize
      @programs = []
      @paths = []
      @debug_root = ""
      @debug_root_set = false
    end

    def add(program, path)
      @programs.push(program)
      @paths.push(path)
      self
    end


    def debug_root(path)
      @debug_root = path
      @debug_root_set = true
      self
    end

    def json
      s = "{\"uprobe_targets\": ["
      i = 0
      while i < @programs.length
        if i > 0
          s += ", "
        end
        s += "{\"program\": \"#{SpinelBPF.json_escape(@programs[i])}\", \"path\": \"#{SpinelBPF.json_escape(@paths[i])}\"}"
        i += 1
      end
      if @debug_root_set
        return s + "], \"debug_root\": \"#{SpinelBPF.json_escape(@debug_root)}\"}"
      end
      s + "]}"
    end
  end


  def self.json_escape(v)
    if v.include?("\"") || v.include?("\\") || v.include?("\n")
      raise ValueRange, "spinelbpf: #{v} has a quote, a backslash or a newline — not accepted as a uprobe program or path"
    end
    v
  end


  def self.global_rows
    rows = []
    lines = SpinelBPFC.spinelbpf_embedded_records.split("\n")
    i = 0
    while i < lines.length
      p = lines[i].split("|")
      if p.length == 5 && p[0] == "G"
        rows.push([p[1], p[2], p[3], p[4]])
      end
      i += 1
    end
    rows
  end


  def self.optional_names
    out = []
    rows = global_rows
    i = 0
    while i < rows.length
      if rows[i][3] == "1"
        out.push(rows[i][0])
      end
      i += 1
    end
    out
  end


  def self.global_row(name)
    rows = global_rows
    i = 0
    while i < rows.length
      if rows[i][0] == name
        return rows[i]
      end
      i += 1
    end
    raise MapMismatch, "spinelbpf: global #{name} is not in this executable (no eBPF program reads or adds it — rebuild, or use it on the eBPF side)"
  end


  def self.global_bits(name, t, v)
    if v.nil?
      raise ValueRange, "spinelbpf: config #{name}: the value is nil (Spinel's Integer has no -2^63)"
    end
    w = t[1, 2].to_i
    if t[0] == "u"
      if v < 0 || (w < 64 && v >= (1 << w))
        raise ValueRange, "spinelbpf: config #{name}: #{v} is outside #{t}"
      end
      return v.to_s
    end
    if w < 64
      lim = 1 << (w - 1)
      if v < -lim || v >= lim
        raise ValueRange, "spinelbpf: config #{name}: #{v} is outside #{t}"
      end
      if v < 0
        return (v + (1 << w)).to_s
      end
      return v.to_s
    end
    if v >= 0
      return v.to_s
    end
    u64_decimal((v >> 32) & 0xFFFFFFFF, v & 0xFFFFFFFF)
  end


  def self.u64_decimal(hi, lo)
    limbs = [hi >> 16, hi & 0xFFFF, lo >> 16, lo & 0xFFFF]
    dec = ""
    while limbs[0] != 0 || limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0
      r = 0
      j = 0
      while j < 4
        cur = r * 65536 + limbs[j]
        limbs[j] = cur / 10
        r = cur % 10
        j += 1
      end
      dec = r.to_s + dec
    end
    dec == "" ? "0" : dec
  end


  def self.global_value(name, t, raw)
    w = t[1, 2].to_i
    if t[0] == "u"
      if w == 64 && raw < 0
        raise ValueRange, "spinelbpf: global #{name}: a u64 value of 2^63 or more does not fit Ruby's Integer"
      end
      return raw
    end
    if w < 64 && raw >= (1 << (w - 1))
      return raw - (1 << w)
    end
    raw
  end



  class ConfigSet
    def initialize
      @names = []
      @bits = []
    end

    def values_set
      @names.length
    end

    def set(g, v)
      put(g.global_name, g.global_type, v)
    end

    def set_optional(g, v)
      put(g.global_name, g.global_type, v)
    end

    def put(name, t, v)
      if SpinelBPF.global_row(name)[1] != "rodata"
        raise MapMismatch, "spinelbpf: #{name} is a Counter (.bss) — it has no load-time value"
      end
      b = SpinelBPF.global_bits(name, t, v)
      i = 0
      while i < @names.length
        if @names[i] == name
          @bits[i] = b
          return self
        end
        i += 1
      end
      @names.push(name)
      @bits.push(b)
      self
    end

    def json(optional)
      s = "{\"set\": {"
      i = 0
      while i < @names.length
        if i > 0
          s += ", "
        end
        s += "\"#{@names[i]}\": #{@bits[i]}"
        i += 1
      end
      s += "}, \"optional\": ["
      i = 0
      while i < optional.length
        if i > 0
          s += ", "
        end
        s += "\"#{optional[i]}\""
        i += 1
      end
      s + "]}"
    end
  end

  def self.policy_version
    SpinelBPFC.spinelbpf_policy_version
  end


  def self.decl(map)
    d = "{\"name\":\"#{map.name}\",\"kind\":\"#{map.kind}\",\"key\":\"#{map.key_type}\",\"value\":\"#{map.value_type}\",\"max_entries\":#{map.max_entries}"
    if map.kind == "lpm_trie"
      d = d + ",\"flags\":1"
    end
    d + "}"
  end



  def self.record_layout(map)
    layout_row(map.name)
  end


  def self.layout_row(row)
    lines = SpinelBPFC.spinelbpf_embedded_records.split("\n")
    i = 0
    while i < lines.length
      parts = lines[i].split("|")
      if parts.length == 3 && parts[0] == row
        fields = parts[2].split(";")
        size = fields[0].split("=")[1].to_i
        members = []
        j = 1
        while j < fields.length
          m = fields[j].split(":")
          members.push([m[0], m[1].to_i, m[2][1, 2].to_i / 8, m[2][0] == "i"])
          j += 1
        end
        return [size, members]
      end
      i += 1
    end
    raise MapMismatch, "spinelbpf: #{row} has no record layout in this executable — rebuild with spinelbpf build"
  end




  def self.record_get(h, map, key)
    lay = record_layout(map)
    size = lay[0]
    buf = Array.new(size, 0)
    check(SpinelBPFC.spinelbpf_map_get_bytes(h, decl(map), key, buf, size))
    vals = []
    members = lay[1]
    i = 0
    while i < members.length
      vals.push(read_member(buf, members[i], map.name, key.to_s))
      i += 1
    end
    vals
  end

  def self.read_member(buf, m, name, key)
    off = m[1]
    n = m[2]
    top = buf[off + n - 1]
    if n == 8 && !m[3] && top >= 0x80
      raise ValueRange, "spinelbpf: #{name}[#{key}].#{m[0]}: the u64 value is 2^63 or more and does not fit Spinel's Integer"
    end
    neg = m[3] && top >= 0x80
    v = 0
    i = n - 1
    while i >= 0
      b = buf[off + i]
      if i == n - 1 && n == 8 && neg
        b = b & 0x7F
      end
      v = (v << 8) | b
      i -= 1
    end
    if neg
      if n == 8
        if v == 0
          raise ValueRange, "spinelbpf: #{name}[#{key}].#{m[0]}: the i64 value -2^63 is Spinel's nil marker (INT64_MIN)"
        end
        return v - 9223372036854775807 - 1
      end
      return v - (1 << (n * 8))
    end
    v
  end


  def self.record_put(h, map, key, rec)
    lay = record_layout(map)
    size = lay[0]
    members = lay[1]
    vals = rec.to_a
    if vals.length != members.length
      raise ValueRange, "spinelbpf: #{map.name}[#{key}]: the record has #{vals.length} members, the layout #{members.length}"
    end
    buf = Array.new(size, 0)
    i = 0
    while i < members.length
      m = members[i]
      v = vals[i]
      check_member(v, m, map.name, key.to_s)
      j = 0
      while j < m[2]
        buf[m[1] + j] = (v >> (8 * j)) & 0xFF
        j += 1
      end
      i += 1
    end
    check(SpinelBPFC.spinelbpf_map_put_bytes(h, decl(map), key, buf, size))
  end


def self.record_put_values(h, map, key, vals)
  lay = record_layout(map)
  size = lay[0]
  members = lay[1]
  if vals.length != members.length
    raise ValueRange, "spinelbpf: #{map.name}[#{key}]: #{vals.length} values, the layout has #{members.length} (array members count element by element)"
  end
  buf = Array.new(size, 0)
  i = 0
  while i < members.length
    m = members[i]
    v = vals[i]
    check_member(v, m, map.name, key.to_s)
    j = 0
    while j < m[2]
      buf[m[1] + j] = (v >> (8 * j)) & 0xFF
      j += 1
    end
    i += 1
  end
  check(SpinelBPFC.spinelbpf_map_put_bytes(h, decl(map), key, buf, size))
end

  def self.check_member(v, m, name, key)
    where = "spinelbpf: #{name}[#{key}].#{m[0]}"
    if v.nil?
      raise ValueRange, "#{where}: nil (or INT64_MIN — Spinel's nil marker) is not a member value"
    end
    if m[0].start_with?("_pad") && v != 0
      raise ValueRange, "#{where}: padding must be 0, got #{v}"
    end
    bits = m[2] * 8
    if m[3]
      if bits < 64 && (v < -(1 << (bits - 1)) || v >= (1 << (bits - 1)))
        raise ValueRange, "#{where}: #{v} is outside i#{bits}"
      end
    elsif v < 0 || (bits < 64 && v >= (1 << bits))
      raise ValueRange, "#{where}: #{v} is outside u#{bits}"
    end
  end



  def self.ring_read(rb, ring, timeout_ms, n)
    lay = record_layout(ring)
    size = lay[0]
    buf = Array.new(size, 0)


    got = 0
    if timeout_ms <= 100
      got = check(SpinelBPFC.spinelbpf_ringbuf_read(rb, timeout_ms, buf, size))
    else
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) / 1_000_000 + timeout_ms
      left = timeout_ms
      while got == 0 && left > 0
        slice = left < 100 ? left : 100
        got = check(SpinelBPFC.spinelbpf_ringbuf_read(rb, slice, buf, size))
        left = deadline - Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond) / 1_000_000
      end
    end
    vals = []
    if got == 0
      return vals
    end
    members = lay[1]
    i = 0
    while i < members.length
      vals.push(read_member(buf, members[i], ring.name, n.to_s))
      i += 1
    end
    vals
  end



  class RingReader
    def initialize(rb, ring)
      @rb = rb
      @ring = ring
      @n = 0
      @owner = SpinelBPF.current_thread
    end

    def own!(what)
      if SpinelBPF.current_thread != @owner
        raise State, "RingReader##{what}: the ring buffer reader belongs to the Thread that opened it — #{what} it there"
      end
    end


    def read_record(timeout_ms)
      own!("read_record")
      v = SpinelBPF.ring_read(@rb, @ring, timeout_ms, @n)
      if v.length > 0
        @n += 1
      end
      v
    end

    def close
      own!("close")
      SpinelBPF.check(SpinelBPFC.spinelbpf_ringbuf_close(@rb))
    end
  end


  def self.int_layout(t, name)
    n = t[1, 2].to_i / 8
    [n, [[name, 0, n, t[0] == "i"]]]
  end

  def self.key_layout(map)
    if map.record_key?
      return layout_row(map.name + ":key")
    end
    int_layout(map.key_type, "key")
  end

  def self.value_layout(map)
    if map.record?
      return layout_row(map.name)
    end
    int_layout(map.value_type, "value")
  end


  def self.pack(lay, vals, name, what)
    members = lay[1]
    if vals.length != members.length
      raise ValueRange, "spinelbpf: #{name} #{what}: #{vals.length} values, the layout has #{members.length} members"
    end
    buf = Array.new(lay[0], 0)
    i = 0
    while i < members.length
      m = members[i]
      v = vals[i]
      check_member(v, m, name, what)
      j = 0
      while j < m[2]
        buf[m[1] + j] = (v >> (8 * j)) & 0xFF
        j += 1
      end
      i += 1
    end
    buf
  end

  def self.unpack(lay, buf, off, name, what)
    vals = []
    members = lay[1]
    i = 0
    while i < members.length
      m = members[i]
      vals.push(read_member(buf, [m[0], m[1] + off, m[2], m[3]], name, what))
      i += 1
    end
    vals
  end


  def self.hash_check(map, rk, rv, api)
    if map.kind != "hash" && map.kind != "lru_hash"
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for hash / lru_hash maps"
    end
    if map.record_key? != rk || map.record? != rv
      raise MapMismatch, "spinelbpf: #{map.name} has a #{map.key_type} key and a #{map.value_type} value — #{api} does not fit it"
    end
  end

  def self.hash_get(h, map, keyvals, rk, rv, api)
    hash_check(map, rk, rv, api)
    kl = key_layout(map)
    vl = value_layout(map)
    kb = pack(kl, keyvals, map.name, "key")
    vb = Array.new(vl[0], 0)
    check(SpinelBPFC.spinelbpf_hash_get(h, decl(map), kb, kl[0], vb, vl[0]))
    unpack(vl, vb, 0, map.name, "value")
  end

  def self.hash_put(h, map, keyvals, vals, rk, rv, api)
    hash_check(map, rk, rv, api)
    kl = key_layout(map)
    vl = value_layout(map)
    kb = pack(kl, keyvals, map.name, "key")
    vb = pack(vl, vals, map.name, "value")
    check(SpinelBPFC.spinelbpf_hash_put(h, decl(map), kb, kl[0], vb, vl[0]))
  end

  def self.hash_delete(h, map, keyvals, rk, api)
    hash_check(map, rk, map.record?, api)
    kl = key_layout(map)
    kb = pack(kl, keyvals, map.name, "key")
    check(SpinelBPFC.spinelbpf_hash_delete(h, decl(map), kb, kl[0])) == 1
  end


  def self.hash_keys(h, map, rk, api)
    hash_check(map, rk, map.record?, api)
    raw_keys(h, map)
  end

  def self.raw_keys(h, map)
    kl = key_layout(map)
    out = Array.new(kl[0] * map.max_entries, 0)
    n = check(SpinelBPFC.spinelbpf_hash_keys(h, decl(map), kl[0], out, map.max_entries))
    keys = []
    i = 0
    while i < n
      keys.push(unpack(kl, out, i * kl[0], map.name, "key"))
      i += 1
    end
    keys
  end


  def self.possible_cpus
    check(SpinelBPFC.spinelbpf_possible_cpus)
  end


  def self.sum(vs)
    s = 0
    i = 0
    while i < vs.length
      s += vs[i]
      i += 1
    end
    s
  end



  def self.lpm_check(map, api)
    if map.kind != "lpm_trie"
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for lpm_trie maps"
    end
  end


  def self.lpm_value(map, v)
    if map.value_type == "i32"
      if v < -0x80000000 || v > 0x7fffffff
        raise ValueRange, "spinelbpf: #{map.name}: #{v} is outside the i32 values [-2147483648, 2147483647]"
      end
      return 0
    end
    if v < 0 || v > 0xffffffff
      raise ValueRange, "spinelbpf: #{map.name}: #{v} is outside the u32 values [0, 4294967295]"
    end
    0
  end


  def self.lpm_signed(map, v)
    if map.value_type == "i32" && v >= 0x80000000
      return v - 0x100000000
    end
    v
  end


  def self.lpm_prefix_len(prefix)
    check(SpinelBPFC.spinelbpf_lpm_prefix(prefix))
  end

  def self.array_only(map, api)
    if map.kind != "array" && map.kind != "devmap" && map.kind != "sockmap"
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for array maps (and devmaps)"
    end
  end


  def self.percpu_check(map, kind, rk, rv, api)
    if map.kind != kind
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for #{kind} maps"
    end
    if map.record_key? != rk || map.record? != rv
      raise MapMismatch, "spinelbpf: #{map.name} has a #{map.key_type} key and a #{map.value_type} value — #{api} does not fit it"
    end
  end


  def self.percpu_get(h, map, keyvals, kind, rk, rv, api)
    percpu_check(map, kind, rk, rv, api)
    kl = key_layout(map)
    vl = value_layout(map)
    ncpu = possible_cpus
    stride = (vl[0] + 7) / 8 * 8
    kb = pack(kl, keyvals, map.name, "key")
    out = Array.new(ncpu * stride, 0)
    check(SpinelBPFC.spinelbpf_percpu_get(h, decl(map), kb, kl[0], out, ncpu * stride))
    vals = []
    i = 0
    while i < ncpu
      vals.push(unpack(vl, out, i * stride, map.name, "value"))
      i += 1
    end
    vals
  end


  def self.percpu_put(h, map, keyvals, per, kind, rk, rv, api)
    percpu_check(map, kind, rk, rv, api)
    kl = key_layout(map)
    vl = value_layout(map)
    ncpu = possible_cpus
    if per.length != ncpu
      raise ValueRange, "spinelbpf: #{map.name}: #{per.length} per-CPU values, the host has #{ncpu} possible CPUs"
    end
    kb = pack(kl, keyvals, map.name, "key")
    vb = []
    i = 0
    while i < ncpu
      b = pack(vl, per[i], map.name, "value")
      j = 0
      while j < b.length
        vb.push(b[j])
        j += 1
      end
      i += 1
    end
    check(SpinelBPFC.spinelbpf_percpu_put(h, decl(map), kb, kl[0], vb, vb.length))
  end

  def self.firsts(vals)
    out = []
    i = 0
    while i < vals.length
      out.push(vals[i][0])
      i += 1
    end
    out
  end

  def self.wraps(vs)
    out = []
    i = 0
    while i < vs.length
      out.push([vs[i]])
      i += 1
    end
    out
  end

  class Link
    def initialize(h)
      @h = h
    end

    def handle
      @h
    end

    def detach
      SpinelBPF.check(SpinelBPFC.spinelbpf_detach(@h))
    end


    def tcx_direction
      r = SpinelBPFC.spinelbpf_tcx_direction(@h)
      if SpinelBPFC.spinelbpf_result_kind(r) == SpinelBPF::OK
        m = SpinelBPFC.spinelbpf_result_message(r)
        SpinelBPFC.spinelbpf_result_free(r)
        return m
      end
      SpinelBPF.check(r)
      ""
    end
  end


  class Loaded
    def initialize(h)
      @h = h
    end

    def handle
      @h
    end

    def attach_xdp(prog, ifname)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_xdp(@h, prog, ifname)))
    end



    def attach_uprobe(prog, pid)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_uprobe(@h, prog, pid)))
    end


    def attach_uretprobe(prog, pid)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_uretprobe(@h, prog, pid)))
    end


    def uprobe_link_file(link)
      r = SpinelBPFC.spinelbpf_uprobe_link_file(@h, link.handle)
      if SpinelBPFC.spinelbpf_result_kind(r) == SpinelBPF::OK
        m = SpinelBPFC.spinelbpf_result_message(r)
        SpinelBPFC.spinelbpf_result_free(r)
        return m
      end
      SpinelBPF.check(r)
      ""
    end



    def attach_tcx(prog, ifname)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_tcx(@h, prog, ifname)))
    end



    def attach_socket(prog, fd)
      SpinelBPF.check(SpinelBPFC.spinelbpf_attach_socket(@h, prog, fd))
      nil
    end




    def attach_cgroup(prog, fd)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_cgroup(@h, prog, fd)))
    end




    def attach_netfilter(prog, pf, hooknum, priority)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_netfilter(@h, prog, pf, hooknum, priority)))
    end



    def attach_netns(prog, fd)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_netns(@h, prog, fd)))
    end




    def test_run_flow_dissector(prog, bytes)
      n = bytes.length
      if n > 0xffff
        raise Other, "spinelbpf: packet length #{n} is outside 0..65535"
      end
      i = 0
      while i < n
        v = bytes[i]
        if v < 0 || v > 255
          raise ValueRange, "spinelbpf: packet byte #{i} is #{v}, outside 0..255"
        end
        i += 1
      end
      r = SpinelBPF.check(SpinelBPFC.spinelbpf_run_flow(@h, prog, bytes, n))
      out = [r]
      i = 0
      while i < 20
        out.push(SpinelBPFC.spinelbpf_flow_key(i))
        i += 1
      end
      out
    end


    def config_get(g)
      global_get(g.global_name)
    end

    def optional_get(g)
      global_get(g.global_name)
    end

    def counter_get(g)
      global_get(g.global_name)
    end

    def global_get(name)
      row = SpinelBPF.global_row(name)
      decl = "{\"name\": \"#{row[0]}\", \"section\": \"#{row[1]}\", \"type\": \"#{row[2]}\"}"
      SpinelBPF.global_value(name, row[2], SpinelBPF.check(SpinelBPFC.spinelbpf_global_get(@h, decl)))
    end



    def attach_fentry(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 0)))
    end

    def attach_fexit(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 1)))
    end

    def attach_kprobe(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 2)))
    end




    def attach_fmod_ret(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 8)))
    end


    def attach_kretprobe(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 4)))
    end



    def attach_raw_tp(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 5)))
    end



    def attach_ksyscall(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 7)))
    end



    def attach_tracepoint(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 6)))
    end



    def test_run_sk_lookup(prog, proto, port)
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_sk_lookup(@h, prog, proto, port))
    end

    def sk_lookup_cookie
      SpinelBPFC.spinelbpf_sk_lookup_cookie
    end



    def test_run_raw_tp(prog, args)
      if args.length < 1 || args.length > 12
        raise SpinelBPF::ValueRange, "test_run_raw_tp takes 1..12 args (u64 args[i] of bpf_raw_tracepoint_args), got #{args.length}"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_raw_tp(@h, prog, args, args.length))
    end



    def attach_tp_btf(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 3)))
    end



    def test_run_tracing(prog, n)
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_tracing(@h, prog, n))
    end



    def map_get(map, key)
      SpinelBPF.array_only(map, "map_get")
      if map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is a record map — read it with map_get_record"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_map_get(@h, SpinelBPF.decl(map), key))
    end


    def unmet
      r = SpinelBPFC.spinelbpf_object_unmet(@h)
      out = []
      if SpinelBPFC.spinelbpf_result_kind(r) == SpinelBPF::OK
        n = SpinelBPFC.spinelbpf_result_unmet_count(r)
        i = 0
        while i < n
          out << SpinelBPFC.spinelbpf_result_unmet(r, i)
          i += 1
        end
        SpinelBPFC.spinelbpf_result_free(r)
        return out
      end
      SpinelBPF.check(r)
      out
    end




    def map_get_record(map, key)
      SpinelBPF.array_only(map, "map_get_record")
      if !map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is not a record map — read it with map_get"
      end
      SpinelBPF.record_get(@h, map, key)
    end


    def map_put(map, key, value)
      SpinelBPF.array_only(map, "map_put")
      if map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is a record map — write it with map_put_record"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_map_put(@h, SpinelBPF.decl(map), key, value))
    end


    def map_put_record(map, key, rec)
      SpinelBPF.array_only(map, "map_put_record")
      if !map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is not a record map — write it with map_put"
      end
      SpinelBPF.record_put(@h, map, key, rec)
    end



def map_put_record_values(map, key, values)
  SpinelBPF.array_only(map, "map_put_record_values")
  if !map.record?
    raise MapMismatch, "spinelbpf: #{map.name} is not a record map — write it with map_put"
  end
  SpinelBPF.record_put_values(@h, map, key, values)
end

    def test_run_xdp(prog, repeat)
      SpinelBPF.check(SpinelBPFC.spinelbpf_test_run_xdp(@h, prog, repeat))
    end



    def test_run_xdp_packet(prog, bytes)
      SpinelBPF.check(SpinelBPFC.spinelbpf_test_run_xdp_packet(@h, prog, bytes, bytes.length))
    end




    def test_run_tc_packet(prog, bytes)
      n = bytes.length
      if n > 0xffff
        raise Other, "spinelbpf: packet length #{n} is outside 0..65535"
      end
      i = 0
      while i < n
        v = bytes[i]
        if v < 0 || v > 255
          raise ValueRange, "spinelbpf: packet byte #{i} is #{v}, outside 0..255"
        end
        i += 1
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_tc_packet(@h, prog, bytes, n))
    end



    def test_run_skb_packet(prog, bytes)
      n = bytes.length
      if n > 0xffff
        raise Other, "spinelbpf: packet length #{n} is outside 0..65535"
      end
      i = 0
      while i < n
        v = bytes[i]
        if v < 0 || v > 255
          raise ValueRange, "spinelbpf: packet byte #{i} is #{v}, outside 0..255"
        end
        i += 1
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_skb_packet(@h, prog, bytes, n))
    end




    def test_run_netfilter(prog, bytes, pf, hook)
      n = bytes.length
      if n > 0xffff
        raise Other, "spinelbpf: packet length #{n} is outside 0..65535"
      end
      i = 0
      while i < n
        v = bytes[i]
        if v < 0 || v > 255
          raise ValueRange, "spinelbpf: packet byte #{i} is #{v}, outside 0..255"
        end
        i += 1
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_netfilter(@h, prog, bytes, n, pf, hook))
    end



    def hash_get(map, k)
      SpinelBPF.hash_get(@h, map, [k], false, false, "hash_get")[0]
    end

    def hash_get_record(map, k)
      SpinelBPF.hash_get(@h, map, [k], false, true, "hash_get_record")
    end

    def hash_get_rk(map, key)
      SpinelBPF.hash_get(@h, map, key.to_a, true, false, "hash_get_rk")[0]
    end

    def hash_get_record_rk(map, key)
      SpinelBPF.hash_get(@h, map, key.to_a, true, true, "hash_get_record_rk")
    end

    def hash_has(map, k)
      begin
        SpinelBPF.hash_get(@h, map, [k], false, map.record?, "hash_has")
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end

    def hash_has_rk(map, key)
      begin
        SpinelBPF.hash_get(@h, map, key.to_a, true, map.record?, "hash_has_rk")
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end

    def hash_put(map, k, v)
      SpinelBPF.hash_put(@h, map, [k], [v], false, false, "hash_put")
    end

    def hash_put_record(map, k, rec)
      SpinelBPF.hash_put(@h, map, [k], rec.to_a, false, true, "hash_put_record")
    end

    def hash_put_rk(map, key, v)
      SpinelBPF.hash_put(@h, map, key.to_a, [v], true, false, "hash_put_rk")
    end

    def hash_put_record_rk(map, key, rec)
      SpinelBPF.hash_put(@h, map, key.to_a, rec.to_a, true, true, "hash_put_record_rk")
    end


    def hash_delete(map, k)
      SpinelBPF.hash_delete(@h, map, [k], false, "hash_delete")
    end

    def hash_delete_rk(map, key)
      SpinelBPF.hash_delete(@h, map, key.to_a, true, "hash_delete_rk")
    end


    def hash_keys(map)
      out = []
      ks = SpinelBPF.hash_keys(@h, map, false, "hash_keys")
      i = 0
      while i < ks.length
        out.push(ks[i][0])
        i += 1
      end
      out
    end

    def hash_keys_rk(map)
      SpinelBPF.hash_keys(@h, map, true, "hash_keys_rk")
    end




    def lpm_put(map, prefix, v)
      SpinelBPF.lpm_check(map, "lpm_put")
      SpinelBPF.lpm_value(map, v)
      st = SpinelBPF.check(SpinelBPFC.spinelbpf_lpm_put(@h, SpinelBPF.decl(map), prefix, v))
      if st == -28
        raise Other, "spinelbpf: lpm_put #{map.name} #{prefix}: ENOSPC — map is full (#{map.max_entries} prefixes; overwriting an existing prefix still works)"
      end
      nil
    end


    def lpm_remove(map, prefix)
      SpinelBPF.lpm_check(map, "lpm_remove")
      SpinelBPF.check(SpinelBPFC.spinelbpf_lpm_remove(@h, SpinelBPF.decl(map), prefix)) == 0
    end


    def lpm_match(map, addr)
      SpinelBPF.lpm_check(map, "lpm_match")
      r = SpinelBPFC.spinelbpf_lpm_match(@h, SpinelBPF.decl(map), addr)
      if SpinelBPFC.spinelbpf_result_kind(r) != SpinelBPF::OK
        SpinelBPF.check(r)
        return 0
      end
      m = SpinelBPFC.spinelbpf_result_message(r)
      v = SpinelBPFC.spinelbpf_result_value(r)
      SpinelBPFC.spinelbpf_result_free(r)
      if m != "found"
        raise NotFound, "spinelbpf: lpm_match #{map.name} #{addr}: no prefix contains the address"
      end
      SpinelBPF.lpm_signed(map, v)
    end


    def lpm_has(map, addr)
      begin
        lpm_match(map, addr)
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end


    def lpm_list(map)
      SpinelBPF.lpm_check(map, "lpm_list")
      r = SpinelBPFC.spinelbpf_lpm_list(@h, SpinelBPF.decl(map))
      if SpinelBPFC.spinelbpf_result_kind(r) != SpinelBPF::OK
        SpinelBPF.check(r)
      end
      m = SpinelBPFC.spinelbpf_result_message(r)
      SpinelBPFC.spinelbpf_result_free(r)
      out = [""]
      out.pop
      lines = m.split("\n")
      i = 0
      while i < lines.length
        f = lines[i].split(" ")
        if f.length == 2
          out.push(f[0] + " " + SpinelBPF.lpm_signed(map, f[1].to_i).to_s)
        end
        i += 1
      end
      out
    end



    def percpu_get(map, k)
      SpinelBPF.firsts(SpinelBPF.percpu_get(@h, map, [k], "percpu_array", false, false, "percpu_get"))
    end

    def percpu_get_record(map, k)
      SpinelBPF.percpu_get(@h, map, [k], "percpu_array", false, true, "percpu_get_record")
    end

    def percpu_put(map, k, vs)
      SpinelBPF.percpu_put(@h, map, [k], SpinelBPF.wraps(vs), "percpu_array", false, false, "percpu_put")
    end

    def percpu_put_record(map, k, recs)
      per = []
      i = 0
      while i < recs.length
        per.push(recs[i].to_a)
        i += 1
      end
      SpinelBPF.percpu_put(@h, map, [k], per, "percpu_array", false, true, "percpu_put_record")
    end

    def percpu_hash_get(map, k)
      SpinelBPF.firsts(SpinelBPF.percpu_get(@h, map, [k], "percpu_hash", false, false, "percpu_hash_get"))
    end

    def percpu_hash_get_record(map, k)
      SpinelBPF.percpu_get(@h, map, [k], "percpu_hash", false, true, "percpu_hash_get_record")
    end

    def percpu_hash_get_rk(map, key)
      SpinelBPF.firsts(SpinelBPF.percpu_get(@h, map, key.to_a, "percpu_hash", true, false, "percpu_hash_get_rk"))
    end

    def percpu_hash_get_record_rk(map, key)
      SpinelBPF.percpu_get(@h, map, key.to_a, "percpu_hash", true, true, "percpu_hash_get_record_rk")
    end

    def percpu_hash_put(map, k, vs)
      SpinelBPF.percpu_put(@h, map, [k], SpinelBPF.wraps(vs), "percpu_hash", false, false, "percpu_hash_put")
    end

    def percpu_hash_put_rk(map, key, vs)
      SpinelBPF.percpu_put(@h, map, key.to_a, SpinelBPF.wraps(vs), "percpu_hash", true, false, "percpu_hash_put_rk")
    end

    def percpu_hash_put_record(map, k, recs)
      per = []
      i = 0
      while i < recs.length
        per.push(recs[i].to_a)
        i += 1
      end
      SpinelBPF.percpu_put(@h, map, [k], per, "percpu_hash", false, true, "percpu_hash_put_record")
    end

    def percpu_hash_put_record_rk(map, key, recs)
      per = []
      i = 0
      while i < recs.length
        per.push(recs[i].to_a)
        i += 1
      end
      SpinelBPF.percpu_put(@h, map, key.to_a, per, "percpu_hash", true, true, "percpu_hash_put_record_rk")
    end

    def percpu_hash_has(map, k)
      begin
        SpinelBPF.percpu_get(@h, map, [k], "percpu_hash", false, map.record?, "percpu_hash_has")
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end

    def percpu_hash_has_rk(map, key)
      begin
        SpinelBPF.percpu_get(@h, map, key.to_a, "percpu_hash", true, map.record?, "percpu_hash_has_rk")
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end

    def percpu_hash_delete(map, k)
      SpinelBPF.percpu_check(map, "percpu_hash", false, map.record?, "percpu_hash_delete")
      kl = SpinelBPF.key_layout(map)
      SpinelBPF.check(SpinelBPFC.spinelbpf_hash_delete(@h, SpinelBPF.decl(map), SpinelBPF.pack(kl, [k], map.name, "key"), kl[0])) == 1
    end

    def percpu_hash_delete_rk(map, key)
      SpinelBPF.percpu_check(map, "percpu_hash", true, map.record?, "percpu_hash_delete_rk")
      kl = SpinelBPF.key_layout(map)
      SpinelBPF.check(SpinelBPFC.spinelbpf_hash_delete(@h, SpinelBPF.decl(map), SpinelBPF.pack(kl, key.to_a, map.name, "key"), kl[0])) == 1
    end

    def percpu_hash_keys(map)
      SpinelBPF.percpu_check(map, "percpu_hash", false, map.record?, "percpu_hash_keys")
      SpinelBPF.firsts(SpinelBPF.raw_keys(@h, map))
    end

    def percpu_hash_keys_rk(map)
      SpinelBPF.percpu_check(map, "percpu_hash", true, map.record?, "percpu_hash_keys_rk")
      SpinelBPF.raw_keys(@h, map)
    end


    def ringbuf(ring)
      RingReader.new(SpinelBPF.check(SpinelBPFC.spinelbpf_ringbuf_open(@h, ring.name)), ring)
    end

    def close
      SpinelBPF.check(SpinelBPFC.spinelbpf_close(@h))
    end
  end
end
