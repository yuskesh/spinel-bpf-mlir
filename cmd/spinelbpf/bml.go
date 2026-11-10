package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

var bmlArchives = []string{"libbml_spinel.a", "libbml.a", "libbpf.a", "libelf.a", "libz.a"}

type versionSet struct {
	BpfMlirCommit string
	PolicyVersion int
	MaxFormat     int
}

func spinelVersions(cfg Config) (versionSet, error) {
	o, err := exec.Command("git", "-C", cfg.Repo, "ls-files", "-s", "third_party/bpf-mlir").Output()
	f := strings.Fields(string(o))
	if err != nil || len(f) < 2 || f[0] != "160000" {
		return versionSet{}, fmt.Errorf("reading the third_party/bpf-mlir gitlink: %v %q", err, o)
	}
	return versionSet{f[1], requirements.PolicyVersion, requirements.MaxFormatVersion}, nil
}

var defineRe = func(name string) *regexp.Regexp { return regexp.MustCompile(`(?m)^#define ` + name + ` +([0-9]+)`) }

func bmlVersions(cfg Config) (versionSet, error) {
	bml := filepath.Join(cfg.Repo, "third_party", "bpf-mlir-loader")
	o, err := exec.Command("git", "-C", bml, "ls-tree", "HEAD", "third_party/bpf-mlir").Output()
	f := strings.Fields(string(o))
	if err != nil || len(f) < 3 || f[1] != "commit" {
		return versionSet{}, fmt.Errorf("reading bpf-mlir-loader's third_party/bpf-mlir gitlink: %v %q", err, o)
	}
	num := func(file, name string) (int, error) {
		b, err := os.ReadFile(filepath.Join(bml, file))
		if err != nil {
			return 0, err
		}
		m := defineRe(name).FindSubmatch(b)
		if m == nil {
			return 0, fmt.Errorf("%s has no #define %s", file, name)
		}
		return strconv.Atoi(string(m[1]))
	}
	p, err := num("src/req/check.h", "BML_POLICY_VERSION")
	if err != nil {
		return versionSet{}, err
	}
	mf, err := num("src/req/req.h", "BML_MAX_FORMAT_VERSION")
	if err != nil {
		return versionSet{}, err
	}
	return versionSet{f[2], p, mf}, nil
}

func compareVersions(sp, bml versionSet) error {
	var bad []string
	if sp.BpfMlirCommit != bml.BpfMlirCommit {
		bad = append(bad, fmt.Sprintf("bpf-mlir commit: spinel %s, bpf-mlir-loader %s", sp.BpfMlirCommit, bml.BpfMlirCommit))
	}
	if sp.PolicyVersion != bml.PolicyVersion {
		bad = append(bad, fmt.Sprintf("judgement (policy) version: spinel's bpf-mlir %d, bpf-mlir-loader %d", sp.PolicyVersion, bml.PolicyVersion))
	}
	if sp.MaxFormat != bml.MaxFormat {
		bad = append(bad, fmt.Sprintf("requirements format maximum: spinel's bpf-mlir %d, bpf-mlir-loader %d", sp.MaxFormat, bml.MaxFormat))
	}
	if len(bad) > 0 {
		return fmt.Errorf("the C loader and the frontend disagree — raise both pins together: %s", strings.Join(bad, "; "))
	}
	return nil
}

func checkBMLVersions(cfg Config) error {
	sp, err := spinelVersions(cfg)
	if err != nil {
		return err
	}
	b, err := bmlVersions(cfg)
	if err != nil {
		return err
	}
	return compareVersions(sp, b)
}
