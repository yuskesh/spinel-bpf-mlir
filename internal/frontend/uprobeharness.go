package frontend

import (
	"fmt"
	"strings"
)

// The uprobe harness. The kernel side starts the target (ARGV[0] — the cfix fixture) as a child process and has it call functions
// on command lines from stdin (the probe fires inside the child). The twin turns the same line into arguments by cfix's convention
// and calls the root. cfix's convention (internal/frontend/testdata/uprobe/target/cfix.c):
//   sum A B C     → sum_args(A, B, C) — arguments 1..3 are integers
//   greet N TEXT  → greet(TEXT, N) — argument 1 is a string (TEXT is the rest of the line; empty means an empty string), 2 an integer
//   null N        → greet(NULL, N)
//   gai HOST SERV → (the child is gfix) libc's getaddrinfo(HOST, SERV, …) — arguments 1 and 2 are strings
//   lock I / unlock I → (the child is mfix) libc's pthread_mutex_lock / unlock(&m[I]) — the child answers the mutex's address, and
//                   the kernel side prints it as rv=. The twin gets `at ADDR` (the raw value as argument 1), or, for a program that
//                   reads no argument, `lock I` / `unlock I` as they are
// Test builds only (it never reaches the user's executable).

// hasUprobe reports whether res has a uprobe program.
func hasUprobe(res *Result) bool {
	for _, p := range res.Programs {
		if p.Kind == "uprobe" || p.Kind == "uretprobe" { // uretprobe uses the same child process
			return true
		}
	}
	return false
}

// hasPtrParam reports whether p has a :ptr argument (the kernel harness then prints the child's answer as rv=).
func hasPtrParam(p *Program) bool {
	for _, kp := range p.Params {
		if kp.Type == "ptr" {
			return true
		}
	}
	return false
}

// uprobeKernelSetup returns the kernel harness's start-up of the child process (inline C for fork, exec and the pipes). It is empty
// when there is no uprobe program.
func uprobeKernelSetup(res *Result) string {
	if !hasUprobe(res) {
		return ""
	}
	return `module HUprobe
  ffi_source <<~C
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    #include <sys/types.h>
    static int h_in = -1;
    static FILE *h_rf = NULL;
    static long h_child = 0;
    static char h_last[1100];
    long h_start(const char *path) {
      int a[2], b[2];
      if (pipe(a) != 0 || pipe(b) != 0) return -1;
      pid_t p = fork();
      if (p < 0) return -1;
      if (p == 0) {
        dup2(a[0], 0); dup2(b[1], 1); close(a[1]); close(b[0]);
        execl(path, path, (char *)0);
        _exit(127);
      }
      close(a[0]); close(b[1]);
      h_in = a[1];
      h_rf = fdopen(b[0], "r");
      h_child = (long)p;
      char line[256];
      if (h_rf == NULL || fgets(line, sizeof line, h_rf) == NULL || strncmp(line, "ready ", 6) != 0) return -1;
      return h_child;
    }
    long h_pid(void) { return h_child; }
    long h_send(const char *s) {
      size_t n = strlen(s);
      char nl = 10; /* newline, by value (the Ruby heredoc expands escapes inside strings) */
      if (write(h_in, s, n) != (ssize_t)n || write(h_in, &nl, 1) != 1) return -1;
      char line[1100];
      if (fgets(line, sizeof line, h_rf) == NULL) return -1;
      strcpy(h_last, line);
      return (long)strlen(line);
    }
    /* the integer in the second word of the child's last answer (the return value of the uretprobe's function) */
    long h_last_value(void) { char *s = strchr(h_last, 32); return s ? strtoll(s + 1, NULL, 10) : 0; }
  C
  ffi_func :h_start, [:str], :long
  ffi_func :h_pid, [], :long
  ffi_func :h_send, [:str], :long
  ffi_func :h_last_value, [], :long
end
if HUprobe.h_start(ARGV[0]) < 0
  raise "the kernel harness could not start the uprobe target #{ARGV[0]} as a child process"
end
`
}

// uprobeTwinRun returns the twin's `run <prog> <cfix command>` (values are cut to the width of the declared params' types — a model
// of the kernel reading a register's bits at that width).
func uprobeTwinRun(kw string, p *Program) string {
	var b strings.Builder
	decl := map[int]string{}
	for _, kp := range p.Params {
		decl[kp.N] = kp.Type
	}
	setInt := func(n int, x string) {
		if t, ok := decl[n]; ok && t == "ptr" { // a pointer's raw value (an i64 not cut to width)
			fmt.Fprintf(&b, "          _h_args[%d] = %s\n", n, x)
		} else if ok && t != "user_str" && t != "user_buf" {
			fmt.Fprintf(&b, "          _h_args[%d] = %s\n", n, widthCut(x, t))
		}
	}
	setStr := func(n int, bytes, null string) {
		if decl[n] == "user_str" {
			fmt.Fprintf(&b, "          _h_strs[%d] = BPF::UserStr.new(%s, %s)\n", n, bytes, null)
		}
	}
	setBuf := func(n int, bytes, null string) { // a :user_buf argument (the memory the pointer points to)
		if decl[n] == "user_buf" {
			fmt.Fprintf(&b, "          _h_bufs[%d] = BPF::UserBuf.new(%s, %s)\n", n, bytes, null)
		}
	}
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_args = Array.new(7, 0)\n        _h_strs = Array.new(7, BPF::UserStr.new(Array.new(0, 0), true))\n        _h_bufs = Array.new(7, BPF::UserBuf.new(Array.new(0, 0), true))\n", kw, p.Name)
	if mutation("ustr-null-status") { // mutation control (test builds only): the twin's NULL status becomes 0
		b.WriteString("        BPF::USTR_NULL_STATUS[0] = 0\n")
	}
	b.WriteString("        if _h_f[2] == \"sum\"\n")
	setInt(1, "_h_f[3].to_i")
	setInt(2, "_h_f[4].to_i")
	setInt(3, "_h_f[5].to_i")
	b.WriteString("        elsif _h_f[2] == \"greet\"\n          _h_txt = \"\"\n          if _h_f.length > 4\n            _h_txt = _h_f[4, _h_f.length - 4].join(\" \")\n          end\n")
	setStr(1, "_h_txt.bytes", "false")
	setInt(2, "_h_f[3].to_i")
	b.WriteString("        elsif _h_f[2] == \"null\"\n")
	setStr(1, "Array.new(0, 0)", "true")
	setInt(2, "_h_f[3].to_i")
	b.WriteString("        elsif _h_f[2] == \"gai\"\n") // gfix's `gai HOST SERV` (libc's getaddrinfo — arguments 1 and 2 are strings)
	setStr(1, "_h_f[3].bytes", "false")
	setStr(2, "_h_f[4].bytes", "false")
	b.WriteString("        elsif _h_f[2] == \"at\"\n") // the twin-only `at ADDR` — argument 1 is the raw value of the pointer the child printed (the kernel side sends `lock I` to mfix and prints rv=)
	setInt(1, "_h_f[3].to_i")
	b.WriteString("        elsif _h_f[2] == \"lock\" || _h_f[2] == \"unlock\"\n")                                                                                                                                                                                                                                                          // for a program that reads no argument (unlock), the twin takes just the command
	b.WriteString("        elsif _h_f[2] == \"put\"\n          _h_bb = Array.new(256, 0)\n          if _h_f.length > 4\n            _h_tb = _h_f[4].bytes\n            _h_i = 0\n            while _h_i < _h_tb.length && _h_i < 256\n              _h_bb[_h_i] = _h_tb[_h_i]\n              _h_i += 1\n            end\n          end\n") // pfix's `put LEN TEXT` — TEXT at the start of a 256-byte zero buffer
	setBuf(1, "_h_bb", "false")
	setInt(2, "_h_f[3].to_i")
	b.WriteString("        elsif _h_f[2] == \"putnull\"\n") // pfix's `putnull LEN` — a NULL buffer
	setBuf(1, "Array.new(0, 0)", "true")
	setInt(2, "_h_f[3].to_i")
	b.WriteString("        else\n          raise \"unknown cfix command #{_h_f[2]}\"\n        end\n")
	fmt.Fprintf(&b, "        %s(BPF::UprobeCtx.new(_h_args, _h_strs, _h_bufs))\n        puts \"ret=0\"\n", p.Name)
	return b.String()
}
