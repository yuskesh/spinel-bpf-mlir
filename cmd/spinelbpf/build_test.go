package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuskesh/spinel-bpf-mlir/internal/toolchain"
)

func copyExample(t *testing.T, dir string) string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoRoot(), "examples", "xdpcount", "xdpcount.rb"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "xdpcount.rb")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

var artefacts = []string{"xdpcount.mlir", "xdpcount.schema.json", "xdpcount.maps.json", "xdpcount.domain.json", "xdpcount.bpf.o", "xdpcount.compile_warnings.txt", "xdpcount_embed.S", "xdpcount_embed.o"}

func TestBuildTwice(t *testing.T) {
	parallel(t)
	cfg, err := defaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, li := range []string{"off", "auto"} {
		cfg.LineInfo = li
		d1, d2 := t.TempDir(), t.TempDir()
		for _, d := range []string{d1, d2} {
			if _, err := Build(cfg, copyExample(t, d)); err != nil {
				t.Fatalf("build (%s): %v", li, err)
			}
		}
		for _, f := range artefacts {
			a, err1 := os.ReadFile(filepath.Join(d1, f))
			b, err2 := os.ReadFile(filepath.Join(d2, f))
			if err1 != nil || err2 != nil {
				t.Fatalf("%s: %v %v", f, err1, err2)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("--line-info=%s: %s differs between two builds", li, f)
			}
		}
	}
}

func TestGoldenArtefacts(t *testing.T) {
	parallel(t)
	cfg, err := defaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	if _, err := Build(cfg, copyExample(t, d)); err != nil {
		t.Fatal(err)
	}
	for _, f := range artefacts {
		got, _ := os.ReadFile(filepath.Join(d, f))
		want, err := os.ReadFile(filepath.Join(repoRoot(), "examples", "xdpcount", f))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from the committed example (run spinelbpf build examples/xdpcount/xdpcount.rb)", f)
		}
	}
}

func fakeTool(t *testing.T, dir, name, version string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	writeExec(t, p, []byte("#!/bin/sh\necho '"+version+"'\n"))
	return p
}

func TestWrongVersionsStopBeforeGenerating(t *testing.T) {
	parallel(t)
	cfg, err := defaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	tools := t.TempDir()
	cases := []struct {
		name string
		mod  func(*Config)
		want string
	}{
		{"ebpf-compile older release", func(c *Config) {
			c.EbpfCompile = fakeTool(t, tools, "ec1", "bpf-mlir go/v0.7.0 (commit 5156c9b0e18d904046d455a368b0ec0458382de3)")
		}, "needs exactly bpf-mlir commit"},
		{"ebpf-compile previous release v0.8.0", func(c *Config) {
			c.EbpfCompile = fakeTool(t, tools, "ec3", "bpf-mlir go/v0.8.0 (commit e973ce8176f5d596d4eb72499887bb82c95a0902)")
		}, "needs exactly bpf-mlir commit"},
		{"ebpf-compile dirty", func(c *Config) {
			c.EbpfCompile = fakeTool(t, tools, "ec2", "bpf-mlir go/v1.19.0-1962-g41b188568-dirty (commit "+toolchain.PinnedCompilerCommit+")")
		}, "modified or unidentified source"},
		{"spinel other commit", func(c *Config) { c.Spinel = fakeTool(t, tools, "sp1", "spinel 2026.09.30+1 (deadbeef) [gcc]") }, "pinned to 086d514d"},
		{"spinel no version line", func(c *Config) { c.Spinel = fakeTool(t, tools, "sp2", "hello") }, "no `spinel <version>"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := cfg
			tc.mod(&c)
			d := t.TempDir()
			_, err := Build(c, copyExample(t, d))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v", tc.want, err)
			}
			ents, _ := os.ReadDir(d)
			if len(ents) != 1 {
				t.Fatalf("the build wrote files before refusing: %v", ents)
			}
		})
	}
}

func TestRefusedProgramWritesOnlyDomainGraph(t *testing.T) {
	parallel(t)
	cfg, err := defaultConfig()
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	p := filepath.Join(d, "bad.rb")
	os.WriteFile(p, []byte("require \"bpf\"\n\ndef prog(ctx)\n  if 1\n  end\n  BPF::XDP_PASS\nend\nBPF.xdp :prog\n"), 0o644)
	_, err = Build(cfg, p)
	if err == nil || !strings.Contains(err.Error(), "SB005") {
		t.Fatalf("want SB005, got %v", err)
	}
	ents, _ := os.ReadDir(d)
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "bad.domain.json,bad.rb" {
		t.Fatalf("files: %v", names)
	}
}
