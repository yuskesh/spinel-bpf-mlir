package frontend

import (
	"fmt"
	"regexp"
	"strings"
)

func NativeTwin(text string, res *Result) (string, error) {
	if err := noTracing(res, "native twin"); err != nil {
		return "", err
	}
	k, err := keptSource(text, res)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(k)
	b.WriteString("# spinelbpf native twin harness\n")
	b.WriteString(recordTwinCode(res))
	b.WriteString("_twin_n = ARGV[0].to_i\n")
	for _, p := range res.Programs {
		fmt.Fprintf(&b, "_twin_other = 0\n_twin_i = 0\nwhile _twin_i < _twin_n\n  if %s(BPF::XdpMd.new(Array.new(64, 0))) != BPF::%s\n    _twin_other += 1\n  end\n  _twin_i += 1\nend\n", p.Name, p.VerdictConst)
		fmt.Fprintf(&b, "puts \"twin %s runs=#{_twin_n} not_%s=#{_twin_other}\"\n", p.Name, p.VerdictConst)
	}
	for _, m := range res.Maps {
		if m.IsLpm() {
			fmt.Fprintf(&b, "puts \"twin %s entries=#{%s._h_list.length}\"\n", m.Name, m.Const)
			continue
		}
		if m.Record != nil {
			fmt.Fprintf(&b, "_twin_k = 0\nwhile _twin_k < %s.max_entries\n  puts \"twin %s[#{_twin_k}]=#{%s.slot(_twin_k).inspect}\"\n  _twin_k += 1\nend\n", m.Const, m.Name, m.Const)
			continue
		}
		fmt.Fprintf(&b, "_twin_k = 0\nwhile _twin_k < %s.max_entries\n  puts \"twin %s[#{_twin_k}]=#{%s.peek(_twin_k)}\"\n  _twin_k += 1\nend\n", m.Const, m.Name, m.Const)
	}
	return b.String(), nil
}

var requireBPF = regexp.MustCompile(`^\s*require\s+"bpf"\s*$`)
