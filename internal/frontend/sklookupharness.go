package frontend

import (
	"fmt"
	"strings"
)

func skHarnessSetup(res *Result) string {
	if !hasKind(res, "sk_lookup") {
		return ""
	}
	return `module HSock
  ffi_source <<~C
    #include <string.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    /* fd of a socket on 127.0.0.1:port (proto 17: UDP bind, 6: TCP bind + listen), -1 on failure */
    long h_sock(long proto, long port) {
      int s = socket(AF_INET, proto == 6 ? SOCK_STREAM : SOCK_DGRAM, 0);
      if (s < 0) return -1;
      struct sockaddr_in a;
      memset(&a, 0, sizeof a);
      a.sin_family = AF_INET;
      a.sin_port = htons((unsigned short)port);
      a.sin_addr.s_addr = htonl(0x7f000001);
      if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || (proto == 6 && listen(s, 1) != 0)) { close(s); return -1; }
      return s;
    }
    /* the cookie (SO_COOKIE) of the socket fd, -1 on failure */
    long h_cookie(long fd) {
      unsigned long long c = 0;
      socklen_t n = sizeof c;
      if (getsockopt((int)fd, SOL_SOCKET, SO_COOKIE, &c, &n) != 0) return -1;
      return (long)c;
    }
  C
  ffi_func :h_sock, [:long, :long], :long
  ffi_func :h_cookie, [:long], :long
end
`
}

func skRun(kw string, p *Program, kernel bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "      %s _h_f[1] == %q\n        _h_pr = _h_f[2].split(\"=\")[1].to_i\n        _h_po = _h_f[3].split(\"=\")[1].to_i\n", kw, p.Name)
	if kernel {
		fmt.Fprintf(&b, "        puts \"ret=#{_h_obj.test_run_sk_lookup(%q, _h_pr, _h_po)}\"\n        puts \"cookie=#{_h_obj.sk_lookup_cookie}\"\n", p.Name)
	} else {
		fmt.Fprintf(&b, "        puts \"ret=#{%s(BPF::SkLookupCtx.new(_h_pr, _h_po))}\"\n", p.Name)
	}
	return b.String()
}

func skCmds(res *Result, kernel bool) string {
	var b strings.Builder
	for _, m := range res.Maps {
		if m.Kind != "sockmap" {
			continue
		}
		fmt.Fprintf(&b, "    elsif _h_cmd == \"sput\" && _h_f[1] == %q\n      _h_pr = 17\n      if _h_f[3] == \"tcp\"\n        _h_pr = 6\n      elsif _h_f[3] != \"udp\"\n        raise \"sput: udp or tcp\"\n      end\n", m.Name)
		if kernel {
			fmt.Fprintf(&b, "      _h_fd = HSock.h_sock(_h_pr, _h_f[4].to_i)\n      if _h_fd < 0\n        raise \"sput: the socket could not be bound\"\n      end\n      _h_obj.map_put(%s, _h_f[2].to_i, _h_fd)\n      puts \"scookie=#{HSock.h_cookie(_h_fd)}\"\n", m.Const)
		} else {
			fmt.Fprintf(&b, "      %s.poke(_h_f[2].to_i, _h_pr)\n      puts \"ok\"\n", m.Const)
		}
	}
	return b.String()
}
