package frontend

func (c *progCtx) isTpCopy(x *Node) bool {
	return x != nil && x.Type == "CallNode" && x.Str["name"] == "copy" && c.prog != nil && c.prog.Kind == "tracepoint" && c.isVarRead(c.a.ref(x, "receiver"), c.param)
}

func (c *progCtx) ctxCopyOtherKind(x *Node) bool {
	if x == nil || x.Type != "CallNode" || x.Str["name"] != "copy" || c.prog == nil || c.prog.Kind == "tracepoint" || c.param == "" || !c.isVarRead(c.a.ref(x, "receiver"), c.param) {
		return false
	}
	k := c.ctxKindOf()
	c.add(Rejected, SB028TracingKind, x, "the %s context has no `copy` — it reads %s", k, ctxReads[k])
	return true
}

func (c *progCtx) tpCopyField(x, at *Node, rf *RecordField, recConst string) (*TpField, bool) {
	if cs, ok := c.callee(x); !ok || cs != "TracepointCtx#copy" {
		if ok {
			c.add(Rejected, SB011ShadowedName, x, "`copy` resolves to %s, not BPF::TracepointCtx#copy", cs)
		}
		return nil, false
	}
	as := args(c.a, x)
	if len(as) != 1 || as[0].Type != "SymbolNode" {
		c.add(Rejected, SB028TracingKind, x, "`%s.copy(:f)` takes one Symbol literal — a byte array field declared in `BPF.tracepoint … fields:`", c.param)
		return nil, false
	}
	fn := as[0].Str["value"]
	var tf *TpField
	for i := range c.prog.TFields {
		if c.prog.TFields[i].Name == fn {
			tf = &c.prog.TFields[i]
		}
	}
	switch {
	case tf == nil:
		c.add(Rejected, SB028TracingKind, as[0], "`%s.copy(:%s)`: %s is not declared in `BPF.tracepoint … fields:` (declare `%s: [offset, [:u8, N]]` from the tracefs format)", c.param, fn, fn, fn)
		return nil, false
	case tf.N == 0:
		c.add(Rejected, SB028TracingKind, as[0], "`%s.copy(:%s)`: %s is declared :%s, not a byte array — read it with `%s.field(:%s)`", c.param, fn, fn, tf.Type, c.param, fn)
		return nil, false
	case rf.Count == 0 || rf.Bits != 8:
		c.add(Rejected, SB028TracingKind, at, "member %s of %s is not an 8-bit array — `%s.copy(:%s)` copies %d bytes into a `[:u8, %d]` member", rf.Name, recConst, c.param, fn, tf.N, tf.N)
		return nil, false
	case rf.Count != tf.N:
		c.add(Rejected, SB028TracingKind, at, "member %s of %s has %d elements but %s is a %d-byte array — the copy is a fixed N bytes, declare the same N", rf.Name, recConst, rf.Count, fn, tf.N)
		return nil, false
	}
	return tf, true
}

func (c *progCtx) tpcopyStmt(n, cp *Node, ref string, m *MapDecl, rf *RecordField) (Stmt, bool) {
	tf, ok := c.tpCopyField(cp, n, rf, m.Record.Const)
	if !ok {
		return Stmt{}, false
	}
	return Stmt{Kind: "tpcopy", Var: ref, Map: m, Field: rf, TpCopy: tf, Pos: c.z.pos(c.a, n)}, true
}

func tpCopyOffset(f *TpField) int64 { return f.Offset }

func hasTpArray(res *Result) bool {
	for _, p := range res.Programs {
		for _, f := range p.TFields {
			if f.N > 0 {
				return true
			}
		}
	}
	return false
}

const hTcpConnectC = `    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <string.h>
    #include <sys/socket.h>
    long h_tcpconnect(long fam) {
      struct sockaddr_storage ss;
      socklen_t sl;
      memset(&ss, 0, sizeof ss);
      if (fam == 6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_addr = in6addr_loopback;
        sl = sizeof *a;
      } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sl = sizeof *a;
      }
      int l = socket(ss.ss_family, SOCK_STREAM, 0);
      if (l < 0) return -1;
      if (bind(l, (struct sockaddr *)&ss, sl) != 0 || listen(l, 1) != 0 || getsockname(l, (struct sockaddr *)&ss, &sl) != 0) { close(l); return -2; }
      int c = socket(ss.ss_family, SOCK_STREAM, 0);
      if (c < 0) { close(l); return -3; }
      if (connect(c, (struct sockaddr *)&ss, sl) != 0) { close(c); close(l); return -4; }
      int s = accept(l, NULL, NULL);
      if (s >= 0) close(s);
      close(c);
      close(l);
      return fam == 6 ? (long)ntohs(((struct sockaddr_in6 *)&ss)->sin6_port) : (long)ntohs(((struct sockaddr_in *)&ss)->sin_port);
    }
`
