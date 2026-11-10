package main

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	parallel(t)
	cfg, _ := defaultConfig()
	d := t.TempDir()
	want := versionFlagWant
	for _, c := range []struct {
		name, flag, commit string
	}{{"vcs", "-buildvcs=true", `\(commit [0-9a-f]{12}(\+dirty)?\)`}, {"novcs", "-buildvcs=false", `\(commit unknown\)`}} {
		bin := filepath.Join(d, c.name)
		b := exec.Command(cfg.Go, append(append([]string{"build", c.flag}, formBuildArgs...), "-o", bin, "./cmd/spinelbpf")...)
		b.Dir = cfg.Repo
		if o, err := b.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v\n%s", c.name, err, o)
		}
		for _, arg := range []string{"--version", "version"} {
			o, err := exec.Command(bin, arg).Output()
			if err != nil || !want.Match(o) || !regexp.MustCompile(c.commit).Match(o) {
				t.Errorf("%s %s (err %v):\n%s", c.name, arg, err, o)
			}
		}
	}
	var so, se strings.Builder
	if rc := run(nil, &so, &se); rc != 2 || !strings.Contains(se.String(), "spinelbpf --version") {
		t.Errorf("run(): rc %d stderr %q", rc, se.String())
	}
}
