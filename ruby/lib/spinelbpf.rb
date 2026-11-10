# spinelbpf — the user-space loader API.
#
# Calls the C loader (libbml from bpf-mlir-loader and spinel's shim — the earlier Go c-archive is gone) through Spinel's FFI. A checked load is the only entry point
# (no unchecked entry point is provided). Each result kind raises its own exception class (the kind is never decided by matching message text).
#
# Reads the three things spinelbpf build embeds in the executable (spinelbpf_elf_*, spinelbpf_schema_sha, spinelbpf_maps_json) through weak symbols
# (so a program without the embedding — a test driver — still links).
#
# **The public API is monomorphic** — argument and return types do not change with the map kind (integer / record) (map_get / map_get_record, map_put / map_put_record).
# Polymorphic returns and arguments corrupt the eBPF-side types of the user's program through Spinel's whole-program inference (measured).
# **The only boundary with the loader is this file's C ABI (spinelbpf_* — result kind, handle, declaration JSON, message)**. The API (load_embedded, map_get, attach_xdp, the exception classes)
# does not depend on Go types or cilium semantics — so that swapping in a loader without Go does not change user code (a design decision).
#
# Spinel's Integer is i64, and INT64_MIN is its nil marker (a known Spinel behavior). When a map value cannot be represented as an Integer
# (u64 at 2^63 or above, signed −2^63), SpinelBPF::ValueRange is raised — never silently turned into a negative number or nil.
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
    /* The current green thread and main (without referring to the Thread constant: a reference would put every program on the threaded runtime.
       These are Spinel-internal functions — current is 0 in a non-threaded program (the test TestSpinelThreadCurrent pins this property) */
    long spinelbpf_thread_current(void) { return (long)sp_Thread_current(); }
    long spinelbpf_thread_main(void) { return (long)sp_Thread_main(); }
    /* tracing: call the C loader's (bml's) public bml_* functions directly (not added to spinel's shim — the same shape as the Mojo frontend). Result handles are
       read by spinelbpf_result_* (bml's results and the shim's results share one handle space — shim/spinel/result.c). int64_t is long on x86_64 */
    #include <string.h>
    long bml_attach_fentry(long obj, const char *prog, long prog_len);
    long bml_attach_fexit(long obj, const char *prog, long prog_len);
    long bml_attach_kprobe(long obj, const char *prog, long prog_len);
    long bml_attach_kretprobe(long obj, const char *prog, long prog_len); /* after attaching, checks the function name and KRETPROBE */
    long bml_attach_tp_btf(long obj, const char *prog, long prog_len); /* after attaching, checks tp_name against the declaration */
    long bml_test_run_tracing(long obj, const char *prog, long prog_len, long n);
    long bml_attach_raw_tp(long obj, const char *prog, long prog_len); /* after attaching, checks the raw tracepoint's name */
    long bml_attach_tracepoint(long obj, const char *prog, long prog_len, long flags); /* to a perf event on every online CPU */
    long bml_attach_ksyscall(long obj, const char *prog, long prog_len); /* a kprobe on the syscall wrapper's entry; after attaching, checks the wrapper's name */
    long bml_test_run_ctx_inout(long obj, const char *prog, long prog_len, unsigned char *ctx_inout, long ctx_len);
    long bml_attach_fmod_ret(long obj, const char *prog, long prog_len); /* after attaching, checks that the link's attach type is MODIFY_RETURN */
    long spinelbpf_attach_trace(long obj, const char *prog, long kind) {
      long n = (long)strlen(prog);
      if (kind == 0) return bml_attach_fentry(obj, prog, n);
      if (kind == 8) return bml_attach_fmod_ret(obj, prog, n);
      if (kind == 1) return bml_attach_fexit(obj, prog, n);
      if (kind == 3) return bml_attach_tp_btf(obj, prog, n);
      if (kind == 4) return bml_attach_kretprobe(obj, prog, n);
      if (kind == 5) return bml_attach_raw_tp(obj, prog, n);
      if (kind == 7) return bml_attach_ksyscall(obj, prog, n);
      if (kind == 6) return bml_attach_tracepoint(obj, prog, n, 0); /* flags 0: an error if the possible and online CPUs differ (a CPU that comes online later is not silently left out) */
      return bml_attach_kprobe(obj, prog, n);
    }
    long spinelbpf_run_tracing(long obj, const char *prog, long n) { return bml_test_run_tracing(obj, prog, (long)strlen(prog), n); }
    /* sk_lookup test run: struct bpf_sk_lookup (the 7.1.8 UAPI — 68 bytes, 72 with padding) — family AF_INET, protocol, remote 127.0.0.1:40000,
       local 127.0.0.1:port (local_port in host order). Returns the program's return value; the selected socket's cookie that the kernel wrote to ctx_out (0 if none) is read with sk_lookup_cookie */
    static unsigned long long spinelbpf_skl_cookie = 0;
    long spinelbpf_run_sk_lookup(long obj, const char *prog, long proto, long port) {
      unsigned char c[72];
      memset(c, 0, sizeof c);
      unsigned int fam = 2, pr = (unsigned int)proto, lp = (unsigned int)port;
      memcpy(c + 8, &fam, 4);
      memcpy(c + 12, &pr, 4);
      c[16] = 127; c[19] = 1;          /* remote_ip4 127.0.0.1 (network order) */
      c[36] = 40000 >> 8; c[37] = 40000 & 255; /* remote_port (network order) */
      c[40] = 127; c[43] = 1;          /* local_ip4 127.0.0.1 */
      memcpy(c + 60, &lp, 4);          /* local_port (host order) */
      long r = bml_test_run_ctx_inout(obj, prog, (long)strlen(prog), c, (long)sizeof c);
      memcpy(&spinelbpf_skl_cookie, c, 8);
      return r;
    }
    long spinelbpf_sk_lookup_cookie(void) { return (long)spinelbpf_skl_cookie; }
    /* raw_tp test run: n integers (1..12 — the library checks) into a u64 args array (n × 8 bytes) */
    long spinelbpf_run_raw_tp(long obj, const char *prog, long *args, long n) {
      unsigned long long a[12] = {0};
      for (long i = 0; i < n && i < 12; i++) a[i] = (unsigned long long)args[i];
      return bml_test_run_ctx_inout(obj, prog, (long)strlen(prog), (unsigned char *)a, n * 8);
    }
    /* sched_cls: tcx attach, the link's direction, and the tc (skb) test run — bml directly, as for tracing. The library (Ruby) checks bytes and length first */
    #include <stdlib.h>
    long bml_attach_tcx(long obj, const char *prog, long prog_len, const char *ifname, long if_len);
    long bml_link_tcx_direction(long link);
    long bml_test_run_tc_data(long obj, const char *prog, long prog_len, const unsigned char *data, long n);
    long spinelbpf_attach_tcx(long obj, const char *prog, const char *ifname) { return bml_attach_tcx(obj, prog, (long)strlen(prog), ifname, (long)strlen(ifname)); }
    long spinelbpf_tcx_direction(long link) { return bml_link_tcx_direction(link); }
    /* socket_filter: SO_ATTACH_BPF to the caller's own socket (no link — value 0) and the skb test run */
    long bml_attach_socket(long obj, const char *prog, long prog_len, long sock_fd);
    long bml_test_run_skb_data(long obj, const char *prog, long prog_len, const unsigned char *data, long n);
    long spinelbpf_attach_socket(long obj, const char *prog, long fd) { return bml_attach_socket(obj, prog, (long)strlen(prog), fd); }
    long bml_attach_cgroup(long obj, const char *prog, long prog_len, long cgroup_fd); /* BPF_LINK_CREATE — returns a link */
    long spinelbpf_attach_cgroup(long obj, const char *prog, long fd) { return bml_attach_cgroup(obj, prog, (long)strlen(prog), fd); }
    long bml_attach_netfilter(long obj, const char *prog, long prog_len, long pf, long hooknum, long priority, long flags); /* in the calling thread's netns */
    long bml_test_run_netfilter(long obj, const char *prog, long prog_len, const unsigned char *data, long n, long pf, long hook);
    long spinelbpf_attach_netfilter(long obj, const char *prog, long pf, long hooknum, long priority) { return bml_attach_netfilter(obj, prog, (long)strlen(prog), pf, hooknum, priority, 0); }
    long bml_attach_netns(long obj, const char *prog, long prog_len, long netns_fd); /* sk_lookup and flow_dissector to a netns through a link */
    long bml_test_run_flow_dissector(long obj, const char *prog, long prog_len, const unsigned char *data, long n, unsigned char *keys_out, long keys_cap);
    long spinelbpf_attach_netns(long obj, const char *prog, long fd) { return bml_attach_netns(obj, prog, (long)strlen(prog), fd); }
    static unsigned char spinelbpf_fk[56]; /* struct bpf_flow_keys of the last flow test run */
    long spinelbpf_run_flow(long obj, const char *prog, long *bytes, long n) {
      unsigned char *b = malloc(n > 0 ? (size_t)n : 1);
      if (!b) abort();
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      memset(spinelbpf_fk, 0, sizeof spinelbpf_fk);
      long r = bml_test_run_flow_dissector(obj, prog, (long)strlen(prog), b, n, spinelbpf_fk, (long)sizeof spinelbpf_fk);
      free(b);
      return r;
    }
    /* The i-th key (in SpinelBPF::FLOW_KEYS order — offsets and widths from the struct bpf_flow_keys UAPI, little endian) */
    long spinelbpf_flow_key(long i) {
      static const int off[20] = {0, 2, 4, 6, 7, 8, 9, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52};
      static const int wid[20] = {2, 2, 2, 1, 1, 1, 1, 2, 2, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
      if (i < 0 || i >= 20) return -1;
      long v = 0;
      for (int k = wid[i] - 1; k >= 0; k--) v = (v << 8) | spinelbpf_fk[off[i] + k];
      return v;
    }
    /* uprobe: targets are a load argument (JSON — bml opens each path once and shares that fd between checking and attaching); attach uses the checked fd; the link's file */
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
      if (!b) abort(); /* at most 64 KiB — do not continue silently if it cannot be allocated */
      for (long i = 0; i < n; i++) b[i] = (unsigned char)bytes[i];
      long r = bml_test_run_tc_data(obj, prog, (long)strlen(prog), b, n);
      free(b);
      return r;
    }
    long spinelbpf_run_skb_packet(long obj, const char *prog, long *bytes, long n) { /* the same shape as run_tc_packet */
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
    /* Global variables: load-time settings (the config JSON) and global reads — bml directly */
    long bml_load_checked_config(const unsigned char *elf, long n, const char *sha, long sha_len, const char *maps, long maps_len, const char *config, long config_len, long caps_kind);
    long bml_global_get(long obj, const char *decl, long decl_len);
    long spinelbpf_load_config(void *elf, long n, const char *sha, const char *maps, const char *config, long caps) {
      return bml_load_checked_config((const unsigned char *)elf, n, sha, (long)strlen(sha), maps, (long)strlen(maps), config, (long)strlen(config), caps);
    }
    long spinelbpf_global_get(long obj, const char *decl) { return bml_global_get(obj, decl, (long)strlen(decl)); }
    /* lpm_trie: bml's bml_lpm_* directly (the shim has no lpm entry). bml reads prefix / address as strings (IPv6, malformed input and set host bits give OTHER
       without touching the kernel). The library checks put values against the declared type first (bml silently truncates to the value width) */
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
  ffi_func :spinelbpf_run_raw_tp, [:long, :str, :int_array, :long], :long # raw_tp test run
  ffi_func :spinelbpf_run_sk_lookup, [:long, :str, :long, :long], :long # sk_lookup test run
  ffi_func :spinelbpf_sk_lookup_cookie, [], :long # cookie of the socket sk_lookup selected
  ffi_func :spinelbpf_attach_tcx, [:long, :str, :str], :long
  ffi_func :spinelbpf_tcx_direction, [:long], :long
  ffi_func :spinelbpf_load_targets, [:ptr, :long, :str, :str, :str, :str, :long], :long
  ffi_func :spinelbpf_attach_uprobe, [:long, :str, :long], :long
  ffi_func :spinelbpf_attach_uretprobe, [:long, :str, :long], :long # uretprobe attach
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
  # Result kinds (the same values as bml's include/bml/kind.h — TestKindTable checks them)
  OK = 0
  KIND_NAMES = ["OK", "SCHEMA_MISMATCH", "PRECHECK_FAILED", "TARGET_REJECTED", "VERIFIER_REJECTED", "OTHER", "STATE", "RUNTIME_CONFLICT", "MAP_MISMATCH", "VALUE_RANGE", "CONFIG_NOT_SET", "NOT_FOUND"]

  # Names of the keys from index 1 on in test_run_flow_dissector's Array (index 0 is the verdict). The order is the offset order of the inline C spinelbpf_flow_key (the struct
  # bpf_flow_keys UAPI). ipv6_src[0] / [1] are the same bytes as ipv4_src / ipv4_dst (a union). Addresses and ports are raw network order
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
  # RuntimeConflict (kind 7) was the Go loader's stage −1 (the Go runtime's signal handler had been replaced) — the C loader (bml) installs no signal handler and never returns it. Kept as a kind name
  class RuntimeConflict < Error
  end
  class MapMismatch < Error
  end
  class ValueRange < Error
  end
  # NotFound means the key is not in the hash map (nil is not returned, to keep a single return type for get).
  class NotFound < Error
  end
  # ConfigNotSet means a required setting (BPF::Config) was not given at load (kind 10 — the message names all of them; no kernel object is created)
  class ConfigNotSet < Error
  end

  # check reads a result handle, returns the value if OK and otherwise raises the kind's exception (the result is freed).
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
      # The non-root hint (user guidance independent of the loader: the C loader's (bml's) message lacks it, the Go loader used to add its own — do not add it twice)
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

  # current_thread is the identity of the current Ruby Thread (0 in a non-threaded program — main only).
  def self.current_thread
    SpinelBPFC.spinelbpf_thread_current
  end

  # main_thread? tells whether this is the main Thread (load only from main).
  def self.main_thread?
    c = SpinelBPFC.spinelbpf_thread_current
    c == 0 || c == SpinelBPFC.spinelbpf_thread_main
  end

  # load_embedded checks the ELF embedded in the executable, then loads it (the only entry point). Main Thread only.
  # A program with globals loads with a config holding no values (only the optional list — a required Config gives ConfigNotSet).
  def self.load_embedded
    load_embedded_config(ConfigSet.new)
  end

  # load_embedded_config loads with load-time settings (SpinelBPF::ConfigSet).
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

  # load_embedded_targets also passes uprobe targets (SpinelBPF::UprobeTargets — program and binary path) as a load argument.
  # bml opens each path only once and with that fd checks the binary's SHA-256, symbol, DWARF types and calling convention; attach_uprobe uses the same fd.
  # A uprobe program without a target is stopped by the check with binary_unknown (TargetRejected — likewise for load_embedded / load_embedded_config).
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

  # UprobeTargets pairs uprobe programs with target binary paths (the argument of load_embedded_targets — it holds no process-wide state).
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

    # debug_root is the root for the build-ID lookup of separate DWARF (bml's targets "debug_root"). If not called, bml's default /usr/lib/debug; "" disables the lookup.
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

  # json_escape gives a value to place in a JSON string — values containing ", \ or a newline are rejected (ValueRange — never silently turned into another path).
  def self.json_escape(v)
    if v.include?("\"") || v.include?("\\") || v.include?("\n")
      raise ValueRange, "spinelbpf: #{v} has a quote, a backslash or a newline — not accepted as a uprobe program or path"
    end
    v
  end

  # global_rows are the G rows of the embedded table ([name, section, type, opt]).
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

  # optional_names lists the OptionalConfig names (the config JSON's optional — if not sent, an unset optional also gives ConfigNotSet).
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

  # global_row is the G row for a name (MapMismatch if missing — a global the program does not use is not in the ELF).
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

  # global_bits turns a value within the declared type's range into the config JSON's bits (unsigned decimal). Out of range gives ValueRange.
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

  # u64_decimal gives the unsigned decimal of the 64 bits made of two 32-bit halves (hi, lo) (Ruby's Integer is i64 here — it cannot hold 2^63 or above directly).
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

  # global_value reads bml's zero-extended bits (an i64 value) as the declared type (i types are sign-extended; u64 at 2^63 or above gives ValueRange).
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

  # ConfigSet holds load-time settings (monomorphic: set for required, set_optional for optional). Its name does not reuse BPF::Config
  # (Spinel renames a class of the same name to BPF__Config, and the frontend's callee match loses BPF::Config#value)
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

  # decl is a map's declaration JSON (the shape of a maps.json element — the loader checks it against the ELF's map rows).
  def self.decl(map)
    d = "{\"name\":\"#{map.name}\",\"kind\":\"#{map.kind}\",\"key\":\"#{map.key_type}\",\"value\":\"#{map.value_type}\",\"max_entries\":#{map.max_entries}"
    if map.kind == "lpm_trie"
      d = d + ",\"flags\":1" # BPF_F_NO_PREALLOC — bml checks the declared flags against the ELF's (other kinds write no flags key — as the current documentation does)
    end
    d + "}"
  end

  # The layout of a record map (an embedded table row `Map|S|size=N;m:off:type;…` — written by spinelbpf build).
  # Returns [size, [[name, offset, bytes, signed], …]] (padding members included — in the same order as the Struct's members).
  def self.record_layout(map)
    layout_row(map.name)
  end

  # layout_row is an embedded table row (`M` for the value, `M:key` for a hash's record key).
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

  # record_get reads a record map's value as bytes and returns an Array of member values (in Struct member order, padding included).
  # The user builds the Struct with explicit arguments (`S.new(v[0], v[1], …)`) — a splat construction in the library (`class.new(*vals)`) makes Spinel's whole-program inference
  # type every record member as untyped and corrupts the eBPF side, and a polymorphic `r[i] = v` silently does nothing (a Spinel defect). u64 at 2^63 or above and i64 −2^63 give ValueRange.
  def self.record_get(h, map, key)
    lay = record_layout(map)
    size = lay[0]
    buf = Array.new(size, 0) # the value's bytes (each 0..255 — Spinel cannot handle IO::Buffer inside a required library)
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
        b = b & 0x7F # assemble without the sign bit and add −2^63 afterwards (so i64 never overflows Integer)
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

  # record_put checks the Struct's members against their type ranges, turns them into bytes and writes them (out of range, nil, or non-zero padding gives ValueRange — never silently truncated).
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

# record_put_values writes a flat Array of values (the same checks as record_put).
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

  # ring_read reads one ring buffer event and returns an Array of member values (a timeout gives an empty Array — a record has at least one member, so it is distinguishable from an event.
  # Ends such as a closed reader or a closed object raise State loudly — never mixed up with a timeout).
  def self.ring_read(rb, ring, timeout_ms, n)
    lay = record_layout(ring)
    size = lay[0]
    buf = Array.new(size, 0)
    # Reads in 100 ms slices (during one long ffi_func call, other Threads wait on GC: a 5 s read was measured to stall them for about 5 s).
    # The meaning is unchanged: a record if an event arrives by the deadline, otherwise a timeout (0). A timeout of 100 ms or less stays a single call
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

  # RingReader is a pull-style ring buffer reader (the mmap mapping stays inside the Go side; events arrive as copies).
  # Only the Thread that opened a RingReader may read and close it (bml silently serializes reads of one reader from different threads: this makes it loud).
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

    # read_record waits for one event (up to timeout_ms) and returns an Array of member values (in BPF.record declaration order, padding included). A timeout gives an empty Array.
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

  # The key and value layouts of a hash map: a record uses its embedded table row, an integer is a single member (name, offset 0, byte count, sign).
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

  # pack checks member values against their type ranges and turns them into bytes (out of range, nil, or non-zero padding gives ValueRange — as in record_put).
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

  # hash_check checks that the API name (record key / value or not) matches the map's kind (MapMismatch otherwise — a monomorphic API).
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

  # hash_keys gives an Array of Arrays of key member values (in the kernel's iteration order — under concurrent changes keys may repeat or be missed).
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

  # possible_cpus is the number of possible CPUs (the length of a per-CPU value Array).
  def self.possible_cpus
    check(SpinelBPFC.spinelbpf_possible_cpus)
  end

  # sum is the sum of an Integer Array (the sum over CPUs of a per-CPU value — for records the user adds member by member).
  def self.sum(vs)
    s = 0
    i = 0
    while i < vs.length
      s += vs[i]
      i += 1
    end
    s
  end

  # array_only makes map_get / map_put etc. accept only array maps (per-CPU arrays use percpu_*).
  # lpm_check checks that the lpm API matches the map's kind (MapMismatch otherwise — a monomorphic API).
  def self.lpm_check(map, api)
    if map.kind != "lpm_trie"
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for lpm_trie maps"
    end
  end

  # lpm_value checks a put value against the declared type's range (:u32 / :i32) (ValueRange outside).
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

  # lpm_signed reads bml's value bits (4 bytes, zero-extended) with the declared sign.
  def self.lpm_signed(map, v)
    if map.value_type == "i32" && v >= 0x80000000
      return v - 0x100000000
    end
    v
  end

  # lpm_prefix_len checks a prefix ("a.b.c.d/n") and returns its length (no object — the kernel is not touched. IPv6, malformed input and set host bits give Other).
  def self.lpm_prefix_len(prefix)
    check(SpinelBPFC.spinelbpf_lpm_prefix(prefix))
  end

  def self.array_only(map, api)
    if map.kind != "array" && map.kind != "devmap" && map.kind != "sockmap" # putting a devmap ifindex or a sockmap socket fd uses the same entry (the key is a u32 index)
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for array maps (and devmaps)"
    end
  end

  # percpu_check checks that the per-CPU API name matches the map's kind (MapMismatch otherwise — a monomorphic API).
  def self.percpu_check(map, kind, rk, rv, api)
    if map.kind != kind
      raise MapMismatch, "spinelbpf: #{map.name} is a #{map.kind} map — #{api} is for #{kind} maps"
    end
    if map.record_key? != rk || map.record? != rv
      raise MapMismatch, "spinelbpf: #{map.name} has a #{map.key_type} key and a #{map.value_type} value — #{api} does not fit it"
    end
  end

  # percpu_get gives an Array of per-CPU Arrays of member values (its length is the number of possible CPUs — the kernel aligns each CPU's value to 8 bytes).
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

  # percpu_put writes per-CPU values (per is an Array of member-value Arrays, one per possible CPU — ValueRange if the length differs).
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

    # tcx_direction is the tcx link's actual direction ("ingress" / "egress" — from the kernel's link info). A non-tcx or detached link gives State
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

  # Loaded is a loaded object.
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

    # attach_uprobe attaches a uprobe program to the entry of the target function checked at load (pid 0 means every process).
    # bml attaches at a file offset in the same fd and, after attaching, checks the offset in the perf link info. A program without a target or of another kind gives State
    def attach_uprobe(prog, pid)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_uprobe(@h, prog, pid)))
    end

    # attach_uretprobe attaches a uretprobe program to the target function's return (targets come from the load's UprobeTargets as for uprobe; pid 0 means every process)
    def attach_uretprobe(prog, pid)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_uretprobe(@h, prog, pid)))
    end

    # uprobe_link_file is the file in a uprobe link's perf link info at attach time
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

    # attach_tcx attaches a sched_cls program to an interface's tcx. The direction is the declared one (`BPF.tcx :p, :ingress`) — bml takes it from the ELF section and,
    # after attaching, checks the direction and ifindex in the kernel's link info (on a mismatch it detaches and gives Other). A non-sched_cls program gives State
    def attach_tcx(prog, ifname)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_tcx(@h, prog, ifname)))
    end

    # attach_socket attaches a socket_filter program to the caller's socket (fd) with SO_ATTACH_BPF. There is no link — detach by closing the socket or with
    # SO_DETACH_BPF (the filter stays on the socket; closing the object does not remove it). A non-socket_filter program gives State; a bad fd gives bml's message (Other)
    def attach_socket(prog, fd)
      SpinelBPF.check(SpinelBPFC.spinelbpf_attach_socket(@h, prog, fd))
      nil
    end

    # attach_cgroup attaches a cgroup_skb program to the caller's cgroup (an fd of a v2 directory) (BPF_LINK_CREATE). The direction is the declared one
    # (`BPF.cgroup_skb :p, :ingress`) — after attaching, bml checks the cgroup and attach type in the link info. A non-cgroup_skb program gives State,
    # a non-cgroup fd gives Other. Detach with Link#detach
    def attach_cgroup(prog, fd)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_cgroup(@h, prog, fd)))
    end

    # attach_netfilter attaches a netfilter program through a link to a hook in **the calling thread's netns**. pf is NFPROTO_IPV4 2 /
    # IPV6 10, hooknum NF_INET_PRE_ROUTING 0 … POST_ROUTING 4, priority an int32, flags 0 (no IP_DEFRAG). After attaching, bml checks the four values
    # in the link info. A non-netfilter program gives State, out of range ValueRange, a kernel rejection Other. Detach with Link#detach
    def attach_netfilter(prog, pf, hooknum, priority)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_netfilter(@h, prog, pf, hooknum, priority)))
    end

    # attach_netns attaches a flow_dissector program through a link to the caller's network namespace (an nsfs fd — /proc/<pid>/ns/net etc.) (bml
    # checks the netns inode in the link info). A program that is not flow_dissector (or sk_lookup) gives State, a non-netns fd Other. Detach with Link#detach
    def attach_netns(prog, fd)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_netns(@h, prog, fd)))
    end

    # test_run_flow_dissector runs a flow_dissector program once on the frame bytes (from the Ethernet header) and returns an Array [verdict, the 20 key values]
    # (key names and order are SpinelBPF::FLOW_KEYS, values are unsigned at the field width, addresses and ports raw network order). After the program the kernel
    # clamps nhoff to [14, n] and thoff to [nhoff, n]. Fewer than 14 bytes gives Other; byte and length checks use the same messages as test_run_tc_packet
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

    # Global reads (monomorphic: separate methods for required, optional and counter). A config gives its load-time value, a counter its current value
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

    # Tracing attach (one method per kind: monomorphic). fentry / fexit attach to a kernel function's entry / exit; for kprobe, bml checks the kernel's
    # func_name against the declaration after attaching (on a mismatch it detaches with an error). A method that does not match the program's kind is a bml error (never passes silently)
    def attach_fentry(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 0)))
    end

    def attach_fexit(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 1)))
    end

    def attach_kprobe(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 2)))
    end

    # attach_fmod_ret attaches an fmod_ret program to a kernel function's entry (it may override the return value: if non-zero the original function is not called).
    # After attaching, bml checks the link's attach type (MODIFY_RETURN) and the target's BTF id. The test run is test_run_tracing (the kernel
    # calls bpf_modify_return_test — the return value is not observed; bml returns the thread's tid)
    def attach_fmod_ret(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 8)))
    end

    # attach_kretprobe attaches a kretprobe program to a function's return (after attaching, bml checks the function name and KRETPROBE)
    def attach_kretprobe(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 4)))
    end

    # attach_raw_tp attaches a raw_tp program to the tracepoint named by its ELF section (after attaching, bml checks the raw tracepoint's name).
    # If an args index the program reads exceeds the tracepoint's argument count, the kernel rejects the attach with -EINVAL
    def attach_raw_tp(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 5)))
    end

    # attach_ksyscall attaches a ksyscall program to the entry of the syscall wrapper (`__x64_sys_<name>`) (after attaching, bml checks the function
    # name in the link info against the wrapper). As with kprobe there is no test run — test by actually calling the syscall
    def attach_ksyscall(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 7)))
    end

    # attach_tracepoint attaches a tracepoint program to the tracefs event named by its ELF section (bml opens a perf event on every online CPU and
    # checks the tracepoint name in the link info). Tracepoint programs have no test run — test by actually triggering the event
    def attach_tracepoint(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 6)))
    end

    # test_run_sk_lookup runs one sk_lookup test run (proto is 17 (UDP) or 6 (TCP), local is 127.0.0.1:port). Returns the program's return value;
    # the selected socket's cookie (0 if none) comes from sk_lookup_cookie
    def test_run_sk_lookup(prog, proto, port)
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_sk_lookup(@h, prog, proto, port))
    end

    def sk_lookup_cookie
      SpinelBPFC.spinelbpf_sk_lookup_cookie
    end

    # test_run_raw_tp runs one raw_tp test run (args are 1..12 integers placed in the u64 args[i]; it runs in the calling thread's context).
    # Returns the program's return value
    def test_run_raw_tp(prog, args)
      if args.length < 1 || args.length > 12
        raise SpinelBPF::ValueRange, "test_run_raw_tp takes 1..12 args (u64 args[i] of bpf_raw_tracepoint_args), got #{args.length}"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_raw_tp(@h, prog, args, args.length))
    end

    # attach_tp_btf attaches a tp_btf program to the tracepoint named by its ELF section (after attaching, bml checks the tracepoint name in the
    # raw tracepoint link info against the declaration). The kernel refuses a tp_btf test run with EFAULT — test by actually triggering the tracepoint
    def attach_tp_btf(prog)
      Link.new(SpinelBPF.check(SpinelBPFC.spinelbpf_attach_trace(@h, prog, 3)))
    end

    # test_run_tracing runs n fentry / fexit test runs without data (the kernel calls bpf_fentry_test1 onward). bml runs them on a short-lived thread
    # other than the caller — the return value is that thread's tid (tid ≠ tgid)
    def test_run_tracing(prog, n)
      SpinelBPF.check(SpinelBPFC.spinelbpf_run_tracing(@h, prog, n))
    end

    # map_get gives an integer map's value (Integer). Record maps use map_get_record (keeping one return type — returning both Integer and Array
    # makes the arguments of the user's `S.new(v[0], …)` untyped, and Spinel's whole-program inference corrupts the record's member types).
    def map_get(map, key)
      SpinelBPF.array_only(map, "map_get")
      if map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is a record map — read it with map_get_record"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_map_get(@h, SpinelBPF.decl(map), key))
    end

    # unmet gives the rows (`kind\tprogram\tname\tdetail`) of the Unmet entries that did not stop the load (requirements that could not be decided — never silently dropped).
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

    # map_put writes an Integer value to a map (out of the value type's range, or INT64_MIN, gives ValueRange — it cannot be told apart from Spinel's nil marker).
    # map_get_record returns an Array of a record map's member values. **The order is the BPF.record declaration order (= the Struct's member order —
    # the frontend enforces the match), padding members included**. Build the Struct with `S.new(v[0], v[1], …)` (if the argument count differs from the member count, the frontend stops with SB024).
    def map_get_record(map, key)
      SpinelBPF.array_only(map, "map_get_record")
      if !map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is not a record map — read it with map_get"
      end
      SpinelBPF.record_get(@h, map, key)
    end

    # map_put writes an Integer to an integer map. Record maps use map_put_record (keeping one argument type — the public API is monomorphic).
    def map_put(map, key, value)
      SpinelBPF.array_only(map, "map_put")
      if map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is a record map — write it with map_put_record"
      end
      SpinelBPF.check(SpinelBPFC.spinelbpf_map_put(@h, SpinelBPF.decl(map), key, value))
    end

    # map_put_record writes a Struct to a record map (member values are checked against their type ranges — out of range, nil, or non-zero padding gives ValueRange).
    def map_put_record(map, key, rec)
      SpinelBPF.array_only(map, "map_put_record")
      if !map.record?
        raise MapMismatch, "spinelbpf: #{map.name} is not a record map — write it with map_put"
      end
      SpinelBPF.record_put(@h, map, key, rec)
    end

# map_put_record_values writes a flat Array of values to a record map (the same order as map_get_record — an array member contributes one value per element, padding included).
# Records with array members are written with this (with map_put_record, a Struct's array member does not match the count and gives ValueRange). Values are an Integer Array only (monomorphic).
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

    # test_run_xdp_packet runs the program once on a packet of bytes (an Integer Array, each 0..255 — otherwise ValueRange) and returns the xdp verdict.
    # The kernel rejects data shorter than 14 bytes (SpinelBPF::Error).
    def test_run_xdp_packet(prog, bytes)
      SpinelBPF.check(SpinelBPFC.spinelbpf_test_run_xdp_packet(@h, prog, bytes, bytes.length))
    end

    # test_run_tc_packet runs a sched_cls program once on a packet (skb) of bytes and returns the verdict (BPF::TC_PASS 0 / TC_DROP 2).
    # Byte and length checks use the same messages as test_run_xdp_packet. The kernel rejects with EINVAL data shorter than 14 bytes and data too short for the ethertype's header (under 34 bytes for IPv4, 54 for IPv6 —
    # net/bpf/test_run.c) (SpinelBPF::Error — with bml's hint)
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

    # test_run_skb_packet runs a socket_filter program once on a frame (skb) of bytes and returns the verdict (BPF::SF_KEEP −1 / SF_DROP 0 — the kernel's retval as int32).
    # Byte and length checks use the same messages as test_run_tc_packet. The kernel strips the 14 Ethernet bytes (len is n − 14); fewer than 14 bytes gives EINVAL (with bml's hint)
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

    # test_run_netfilter runs a netfilter program once on a packet of bytes and returns the verdict (BPF::NF_ACCEPT 1 / NF_DROP 0). pf is 2 / 10,
    # hook 0–4 (otherwise bml's ValueRange). The kernel treats the bytes as an IP packet for LOCAL_OUT (3) (len is n) and as an Ethernet frame for other hooks (len is n − 14).
    # Byte and length checks use the same messages as test_run_tc_packet
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

    # Hash maps (one argument and return type per name): integer keys use hash_*, record keys (`K.new(…)`) hash_*_rk, record values *_record.
    # get of a missing key raises SpinelBPF::NotFound (never returns nil), put of a new key into a full hash gives Other (E2BIG), out of range or non-zero padding gives ValueRange.
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

    # hash_delete is true if it removed an existing key, false if there was none (other errors raise).
    def hash_delete(map, k)
      SpinelBPF.hash_delete(@h, map, [k], false, "hash_delete")
    end

    def hash_delete_rk(map, key)
      SpinelBPF.hash_delete(@h, map, key.to_a, true, "hash_delete_rk")
    end

    # hash_keys gives an Integer Array of keys, hash_keys_rk an Array of Arrays of key member values (make Structs with `K.new(k[0], …)`).
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

    # lpm_trie maps (IPv4 longest-prefix match). A prefix is the string "a.b.c.d/n", an address "a.b.c.d" (bml parses them — IPv6, malformed input and prefixes with host bits set
    # give Other without touching the kernel, and the message names the fix). Values are checked against the declared type's range (:u32 / :i32) (ValueRange outside — bml silently truncates to the value width).
    # lpm_put writes (a new prefix when full gives Other with ENOSPC — the same shape as hash_put's E2BIG; overwriting an existing prefix succeeds even when full).
    def lpm_put(map, prefix, v)
      SpinelBPF.lpm_check(map, "lpm_put")
      SpinelBPF.lpm_value(map, v)
      st = SpinelBPF.check(SpinelBPFC.spinelbpf_lpm_put(@h, SpinelBPF.decl(map), prefix, v))
      if st == -28
        raise Other, "spinelbpf: lpm_put #{map.name} #{prefix}: ENOSPC — map is full (#{map.max_entries} prefixes; overwriting an existing prefix still works)"
      end
      nil
    end

    # lpm_remove removes a prefix (true if removed, false if absent — as hash_delete).
    def lpm_remove(map, prefix)
      SpinelBPF.lpm_check(map, "lpm_remove")
      SpinelBPF.check(SpinelBPFC.spinelbpf_lpm_remove(@h, SpinelBPF.decl(map), prefix)) == 0
    end

    # lpm_match gives the value of the longest match for an address (the kernel's lookup — NotFound if none, as hash_get).
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

    # lpm_has tells whether some prefix contains the address.
    def lpm_has(map, addr)
      begin
        lpm_match(map, addr)
      rescue SpinelBPF::NotFound
        return false
      end
      true
    end

    # lpm_list gives an "a.b.c.d/n v" line for every prefix and value (in bml's order — the lines' byte order; v is decimal with the declared sign).
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

    # Per-CPU maps (monomorphic: an Array per CPU, of length SpinelBPF.possible_cpus). percpu_array uses percpu_*, percpu_hash percpu_hash_* (record keys _rk).
    # A user-space put can overwrite the program's additions (additions between the read and the write are lost — use on a quiescent table).
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

    # ringbuf opens a reader on a ring buffer (BPF::RingBuf). Closing the object first closes any open reader (a later read gives State).
    def ringbuf(ring)
      RingReader.new(SpinelBPF.check(SpinelBPFC.spinelbpf_ringbuf_open(@h, ring.name)), ring)
    end

    def close
      SpinelBPF.check(SpinelBPFC.spinelbpf_close(@h))
    end
  end
end
