package frontend

// Harness triggers for the embedded kernel-struct path (a kernel_type member that is itself a struct, read in place).

// hasKpath reports whether some kernel_type declares an embedded struct member ([:struct, S]); it is the trigger for the
// harness's tcpsend helper.
func hasKpath(res *Result) bool {
	for _, d := range res.KernelTypes {
		for _, f := range d.Fields {
			if f.Kind == "struct" {
				return true
			}
		}
	}
	return false
}

// hTcpSendC is the harness's `tcpsend <n>`: it listens on 127.0.0.2 port 0, a client bound to 127.0.0.1 connects and sends one byte
// (tcp_sendmsg runs on the client's socket — the destination is 127.0.0.2 and the listening port, the source port is the client's port),
// then it accepts and closes everything.
// h_tcpsend returns the listening port and h_tcpsend_cport the port of the last client (errors are negative).
const hTcpSendC = `    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <string.h>
    #include <sys/socket.h>
    static long h_ts_cport = 0;
    long h_tcpsend(void) {
      struct sockaddr_in s, c;
      socklen_t sl = sizeof s;
      memset(&s, 0, sizeof s);
      memset(&c, 0, sizeof c);
      s.sin_family = AF_INET;
      s.sin_addr.s_addr = htonl(0x7f000002);
      c.sin_family = AF_INET;
      c.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      int l = socket(AF_INET, SOCK_STREAM, 0);
      if (l < 0) return -1;
      if (bind(l, (struct sockaddr *)&s, sizeof s) != 0 || listen(l, 1) != 0 || getsockname(l, (struct sockaddr *)&s, &sl) != 0) { close(l); return -2; }
      int k = socket(AF_INET, SOCK_STREAM, 0);
      if (k < 0) { close(l); return -3; }
      sl = sizeof c;
      if (bind(k, (struct sockaddr *)&c, sizeof c) != 0 || connect(k, (struct sockaddr *)&s, sizeof s) != 0 || getsockname(k, (struct sockaddr *)&c, &sl) != 0) { close(k); close(l); return -4; }
      h_ts_cport = (long)ntohs(c.sin_port);
      char b = 'x';
      long r = send(k, &b, 1, 0) == 1 ? 0 : -5;
      int a = accept(l, NULL, NULL);
      if (a >= 0) close(a);
      close(k);
      close(l);
      return r == 0 ? (long)ntohs(s.sin_port) : r;
    }
    long h_tcpsend_cport(void) { return h_ts_cport; }
`

// kaddrRead lowers `t.addr` (bpf-mlir's ebpf.kptr.addr): all 64 bits of the address of a checked (present) kernel pointer, as an i64.
// Use of a nullable `q` outside the then branch of its check is stopped earlier by kcheckedRoot (program.go — SB005).
// The value spans the whole signed i64 range (kernel addresses are negative).
func (c *progCtx) kaddrRead(n, recv *Node, p Pos) *Expr {
	t := recv.Str["name"]
	if cs, ok := c.callee(n); !ok || cs != "KPtr#addr" {
		if ok {
			c.add(Rejected, SB011ShadowedName, n, "`addr` resolves to %s, not BPF::KPtr#addr", cs)
		}
		return nil
	}
	if len(args(c.a, n)) != 0 {
		c.add(Rejected, SB033KernelTypeShape, n, "`%s.addr` takes no arguments — it is the address of the checked kernel pointer", t)
		return nil
	}
	e := &Expr{Kind: "kaddr", Var: t, Path: c.kptrs[t].Name, Pos: p}
	e.Iv = widthRange(64, true)
	return e
}

// hasKaddr reports whether some program reads the address of a blk_mq request — recognised by the kernel_type name "request".
// It is the trigger for the harness's odirect helper.
func hasKaddr(res *Result) bool {
	for _, d := range res.KernelTypes {
		if d.Name == "request" {
			return true
		}
	}
	return false
}

// hODirectC is the harness's `odirect <dir> <n>`: it writes 64 KiB to its own file in dir (which must be on a block device — tmpfs
// gives -9), calls fdatasync, then reads the first 4 KiB n times with O_DIRECT (it does not change the host's queue, scheduler or
// mounts). h_od_sector returns the expected sector, computed from the physical byte of the first extent reported by FIEMAP and the
// start of the partition holding the file's device (/sys/dev/block/MAJ:MIN/start — in 512-byte sectors); errors are negative.
const hODirectC = `    #include <fcntl.h>
    #ifndef O_DIRECT
    #define O_DIRECT 040000
    #endif
    #include <linux/fiemap.h>
    #include <linux/fs.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/ioctl.h>
    #include <sys/stat.h>
    #include <sys/sysmacros.h>
    #include <sys/vfs.h>
    #include <unistd.h>
    static long h_od_sec = -1;
    long h_odirect(const char *d, long n) {
      struct statfs sf;
      if (statfs(d, &sf) != 0 || sf.f_type == 0x01021994) return -9;
      char p[4096];
      snprintf(p, sizeof p, "%s/e155-odirect-%ld", d, (long)getpid());
      int fd = open(p, O_CREAT | O_TRUNC | O_WRONLY, 0600);
      if (fd < 0) return -1;
      char b[65536];
      memset(b, 0x5a, sizeof b);
      if (write(fd, b, sizeof b) != (ssize_t)sizeof b || fdatasync(fd) != 0) { close(fd); unlink(p); return -2; }
      close(fd);
      fd = open(p, O_RDONLY | O_DIRECT);
      if (fd < 0) { unlink(p); return -3; }
      struct { struct fiemap f; struct fiemap_extent e[1]; } fm;
      memset(&fm, 0, sizeof fm);
      fm.f.fm_length = ~0ULL;
      fm.f.fm_flags = FIEMAP_FLAG_SYNC;
      fm.f.fm_extent_count = 1;
      struct stat st;
      h_od_sec = -4;
      if (ioctl(fd, FS_IOC_FIEMAP, &fm) == 0 && fm.f.fm_mapped_extents >= 1 && fstat(fd, &st) == 0) {
        char sp[128];
        snprintf(sp, sizeof sp, "/sys/dev/block/%u:%u/start", major(st.st_dev), minor(st.st_dev));
        FILE *sf2 = fopen(sp, "r");
        long start = 0;
        if (sf2) { if (fscanf(sf2, "%ld", &start) != 1) start = -1; fclose(sf2); }
        h_od_sec = start < 0 ? -5 : start + (long)(fm.e[0].fe_physical / 512);
      }
      void *buf = NULL;
      if (posix_memalign(&buf, 4096, 4096) != 0) { close(fd); unlink(p); return -6; }
      long ok = 0;
      for (long i = 0; i < n; i++) if (pread(fd, buf, 4096, 0) == 4096) ok++;
      free(buf);
      close(fd);
      unlink(p);
      return ok;
    }
    long h_od_sector(void) { return h_od_sec; }
`
