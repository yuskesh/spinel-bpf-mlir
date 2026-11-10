package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/spinel-bpf-mlir/internal/frontend"
)

var seamOutputs = []struct{ key, dir, ext string }{
	{"mlir", "E", ".mlir"}, {"schema", "E", ".schema.json"}, {"maps", "E", ".maps.json"},
	{"records", "E", ".records.txt"}, {"uprobe_targets", "E", ".uprobe_targets.json"}, {"domain", "I", ".domain.json"},
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type seamFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type seamManifest struct {
	Version   int       `json:"version"`
	Source    seamFile  `json:"source"`
	Facts     *seamFile `json:"facts"`
	Execution string    `json:"execution"`
	Pins      struct {
		Spinel struct {
			Commit           string  `json:"commit"`
			ProducerRevision string  `json:"producer_revision"`
			ProducerSource   string  `json:"producer_source"`
			BinarySHA256     *string `json:"binary_sha256"`
		} `json:"spinel"`
		Consumer struct {
			Commit string `json:"commit"`
			Dirty  bool   `json:"dirty"`
		} `json:"consumer"`
		BPFMLIR struct {
			Commit string `json:"commit"`
		} `json:"bpf_mlir"`
	} `json:"pins"`
	Result struct {
		RC             int     `json:"rc"`
		DomainProduced bool    `json:"domain_produced"`
		FailureStage   *string `json:"failure_stage"`
	} `json:"result"`
	Outputs map[string]seamFile `json:"outputs"`
}

type seamTargets struct {
	Version  int `json:"version"`
	Programs []struct {
		Name       string `json:"name"`
		Kind       string `json:"kind"`
		BinaryPath string `json:"binary_path"`
		Decl       struct {
			File string `json:"file"`
			Line int    `json:"line"`
			Col  int    `json:"col"`
		} `json:"decl"`
	} `json:"programs"`
}

type seamInput struct {
	Output   *frontend.Output
	Files    map[string]string
	Decl     map[string]frontend.Pos
	Manifest []byte
}

func seamErr(format string, args ...any) error {
	return fmt.Errorf("seam: "+format, args...)
}

func requireKeys(raw []byte, where string, want ...string) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return seamErr("%s is not a JSON object: %v", where, err)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return seamErr("%s has no key %q", where, k)
		}
	}
	return nil
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func readSeamManifest(path string) (*seamManifest, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, seamErr("reading the inspection manifest: %v", err)
	}
	var m seamManifest
	if err := requirements.DecodeStrictJSON(b, &m); err != nil {
		return nil, nil, seamErr("%s: %v", path, err)
	}
	if m.Version != 1 {
		return nil, nil, seamErr("%s: manifest version %d (this spinelbpf reads version 1)", path, m.Version)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(b, &top); err != nil {
		return nil, nil, seamErr("%s: %v", path, err)
	}
	for _, c := range []struct {
		raw   []byte
		where string
		keys  []string
	}{
		{b, "the manifest", []string{"version", "source", "facts", "execution", "pins", "result", "outputs"}},
		{top["source"], "source", []string{"path", "sha256"}},
		{top["pins"], "pins", []string{"spinel", "consumer", "bpf_mlir"}},
		{top["result"], "result", []string{"rc", "domain_produced"}},
	} {
		if err := requireKeys(c.raw, c.where, c.keys...); err != nil {
			return nil, nil, err
		}
	}
	var pins map[string]json.RawMessage
	_ = json.Unmarshal(top["pins"], &pins)
	for k, keys := range map[string][]string{"spinel": {"commit", "producer_revision", "producer_source"}, "consumer": {"commit", "dirty"}, "bpf_mlir": {"commit"}} {
		if err := requireKeys(pins[k], "pins."+k, keys...); err != nil {
			return nil, nil, err
		}
	}
	if !hex64.MatchString(m.Source.SHA256) {
		return nil, nil, seamErr("source.sha256 %q is not 64 hex digits", m.Source.SHA256)
	}
	switch m.Execution {
	case "consumer":
		if m.Facts == nil || !hex64.MatchString(m.Facts.SHA256) {
			return nil, nil, seamErr("execution consumer needs facts {path, sha256} with a 64-hex sha256")
		}
		if m.Pins.Spinel.ProducerSource != "facts" || m.Pins.Spinel.BinarySHA256 != nil {
			return nil, nil, seamErr("execution consumer needs pins.spinel.producer_source \"facts\" and no binary_sha256, got %q", m.Pins.Spinel.ProducerSource)
		}
	case "source_pipeline":
		if m.Facts != nil {
			return nil, nil, seamErr("execution source_pipeline needs facts null")
		}
		if m.Pins.Spinel.ProducerSource != "metadata" || m.Pins.Spinel.BinarySHA256 == nil || !hex64.MatchString(*m.Pins.Spinel.BinarySHA256) {
			return nil, nil, seamErr("execution source_pipeline needs pins.spinel.producer_source \"metadata\" with a 64-hex binary_sha256")
		}
	default:
		return nil, nil, seamErr("unknown execution %q (consumer or source_pipeline)", m.Execution)
	}
	if !hex40.MatchString(m.Pins.BPFMLIR.Commit) {
		return nil, nil, seamErr("pins.bpf_mlir.commit %q is not a 40-hex commit", m.Pins.BPFMLIR.Commit)
	}
	for k, f := range m.Outputs {
		if !hex64.MatchString(f.SHA256) {
			return nil, nil, seamErr("outputs.%s.sha256 %q is not 64 hex digits", k, f.SHA256)
		}
	}
	return &m, b, nil
}

func bpfMLIRCommit(cfg Config, verified string) (string, error) {
	if verified != "" {
		return verified, nil
	}
	return unverifiedBPFMLIRCommit(cfg)
}

func readSeam(cfg Config, abs, name, bpfCommit string) (*seamInput, error) {
	m, mb, err := readSeamManifest(filepath.Join(cfg.SeamInspect, name+".inspect-manifest.json"))
	if err != nil {
		return nil, err
	}
	src, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(src); got != m.Source.SHA256 {
		return nil, seamErr("%s has sha256 %s but the manifest's source.sha256 is %s — the consumer's output was not made from this source", filepath.Base(abs), got, m.Source.SHA256)
	}
	if m.Pins.BPFMLIR.Commit != bpfCommit {
		return nil, seamErr("the manifest's pins.bpf_mlir.commit is %s but this spinelbpf's bpf-mlir is %s", m.Pins.BPFMLIR.Commit, bpfCommit)
	}
	var want []string
	switch {
	case m.Result.FailureStage != nil:
		return nil, seamErr("the consumer failed at stage %s (manifest result.rc %d) — see the consumer's stderr", *m.Result.FailureStage, m.Result.RC)
	case m.Result.RC == 0:
		for _, o := range seamOutputs {
			want = append(want, o.key)
		}
	case m.Result.RC == 1:
		want = []string{"domain"}
	default:
		return nil, seamErr("manifest result.rc %d (0 or 1)", m.Result.RC)
	}
	if !m.Result.DomainProduced {
		return nil, seamErr("manifest result.domain_produced is false — the consumer produced no domain")
	}
	var keys []string
	for k := range m.Outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(want)
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		return nil, seamErr("manifest result.rc %d needs outputs {%s}, got {%s}", m.Result.RC, strings.Join(want, ", "), strings.Join(keys, ", "))
	}
	data := map[string][]byte{}
	for _, o := range seamOutputs {
		f, ok := m.Outputs[o.key]
		if !ok {
			continue
		}
		dir := cfg.SeamEmit
		if o.dir == "I" {
			dir = cfg.SeamInspect
		}
		p := filepath.Join(dir, name+o.ext)
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, seamErr("outputs.%s: %v", o.key, err)
		}
		if got := sha256Hex(b); got != f.SHA256 {
			return nil, seamErr("outputs.%s: %s has sha256 %s but the manifest says %s", o.key, p, got, f.SHA256)
		}
		data[o.key] = b
	}
	roots, ds, err := frontend.ReadDomainGraph(data["domain"])
	if err != nil {
		return nil, seamErr("outputs.domain: %v", err)
	}
	in := &seamInput{Output: &frontend.Output{Domain: data["domain"], Result: &frontend.Result{Diags: ds}}, Manifest: mb}
	if m.Result.RC == 1 {
		if !ds.Blocking() {
			return in, seamErr("the consumer refused (manifest result.rc 1) but the domain has no blocking diagnostic — see the consumer's stderr")
		}
		return in, &frontend.Error{Diags: ds}
	}
	if ds.Blocking() {
		return in, seamErr("manifest result.rc 0 but the domain has a blocking diagnostic")
	}
	if _, err := bindrt.ParseMapDecls(data["maps"]); err != nil {
		return in, seamErr("outputs.maps: %v", err)
	}
	if !seamRecordsOK(string(data["records"])) {
		return in, seamErr("outputs.records: a character outside the embedded records table's alphabet")
	}
	in.Output.MLIR, in.Output.Schema, in.Output.Maps, in.Output.Records = string(data["mlir"]), data["schema"], data["maps"], string(data["records"])
	in.Files, in.Decl, err = seamUprobes(data["uprobe_targets"], roots)
	if err != nil {
		return in, err
	}
	return in, nil
}

func seamUprobes(b []byte, roots []frontend.DomainRoot) (map[string]string, map[string]frontend.Pos, error) {
	var t seamTargets
	if err := requirements.DecodeStrictJSON(b, &t); err != nil {
		return nil, nil, seamErr("outputs.uprobe_targets: %v", err)
	}
	if err := requireKeys(b, "uprobe_targets", "version", "programs"); err != nil {
		return nil, nil, err
	}
	if t.Version != 1 {
		return nil, nil, seamErr("outputs.uprobe_targets: version %d (this spinelbpf reads version 1)", t.Version)
	}
	want := map[string]frontend.DomainRoot{}
	for _, r := range roots {
		if r.Kind == "uprobe" || r.Kind == "uretprobe" {
			want[r.Name] = r
		}
	}
	files, decl := map[string]string{}, map[string]frontend.Pos{}
	for _, p := range t.Programs {
		r, ok := want[p.Name]
		pos := frontend.Pos{File: p.Decl.File, Line: p.Decl.Line, Col: p.Decl.Col}
		if !ok || r.Kind != p.Kind || r.Decl != pos || p.BinaryPath == "" {
			return nil, nil, seamErr("outputs.uprobe_targets: program %s (%s at %s, binary %q) does not match a uprobe / uretprobe root of the domain", p.Name, p.Kind, pos, p.BinaryPath)
		}
		if _, dup := files[p.Name]; dup {
			return nil, nil, seamErr("outputs.uprobe_targets: program %s appears twice", p.Name)
		}
		files[p.Name], decl[p.Name] = p.BinaryPath, pos
	}
	for n := range want {
		if _, ok := files[n]; !ok {
			return nil, nil, seamErr("outputs.uprobe_targets: the domain's %s root %s has no target", want[n].Kind, n)
		}
	}
	return files, decl, nil
}

func seamRecordsOK(records string) bool {
	return !bytes.ContainsFunc([]byte(records), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("_|=:;[]\n", r))
	})
}
