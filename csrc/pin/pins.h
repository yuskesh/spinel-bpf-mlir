/* csrc/pin/pins.h - the pins of the C build path, in one place.
 * Dev form: the development build's values of internal/toolchain and internal/version (BML, Spinel, Version).
 * Public form (-DSPINELBPF_PUBLIC): the values of internal/toolchain/pin_release.go.
 * A Go test (TestCPinsMatchGo) compares every value here with the Go constants and the submodule gitlinks, so a pin raised in
 * one place and not the other fails the gate instead of passing silently.
 * Policy version and format limit are the bpf-mlir source's own (go/requirements/spec.go); the dev check reads them from the
 * pinned source when a repo is given, and uses these values otherwise. */
#ifndef SPINELBPF_PINS_H
#define SPINELBPF_PINS_H

#define PIN_VERSION "v0.11.0"
#define PIN_SPINEL_COMMIT "0d58c397"

#ifndef SPINELBPF_PUBLIC
#define PIN_PUBLIC 0
#define PIN_COMPILER_COMMIT "1a58c8d6ef57262dfaf68989c370925caddc66f9"
#define PIN_MODULE "github.com/yuskesh/bpf-mlir/go"
#define PIN_MODULE_VERSION "v1.23.1-0.20261124212155-1a58c8d6ef57"
#define PIN_BML_COMMIT "8ad2e0b" /* prefix of the third_party/bpf-mlir-loader gitlink */
#define PIN_BML_COMMIT_FULL "8ad2e0b05434f6bd6c47618525982fd56ca5e9f4" /* the whole gitlink: the 7-digit form is only for text */
#define PIN_POLICY_VERSION 27
#define PIN_MAX_FORMAT 32
#else
#define PIN_PUBLIC 1
#define PIN_COMPILER_VERSION "v1.23.0"
#define PIN_COMPILER_COMMIT "1a58c8d6ef57262dfaf68989c370925caddc66f9"
#define PIN_MODULE "github.com/yuskesh/go-bpf-mlir"
#define PIN_MODULE_VERSION "v0.21.0"
#define PIN_BML_VERSION "v0.2.0"
#define PIN_BML_COMMIT "8ad2e0b05434f6bd6c47618525982fd56ca5e9f4"
#define PIN_BML_COMMIT_FULL PIN_BML_COMMIT
#define PIN_POLICY_VERSION 27
#define PIN_MAX_FORMAT 32
#endif

/* The public pins are always present for the test that compares them with pin_release.go, whatever the form. */
#define PIN_RELEASE_COMPILER_VERSION "v1.23.0"
#define PIN_RELEASE_COMPILER_COMMIT "1a58c8d6ef57262dfaf68989c370925caddc66f9"
#define PIN_RELEASE_MODULE "github.com/yuskesh/go-bpf-mlir"
#define PIN_RELEASE_MODULE_VERSION "v0.21.0"
#define PIN_RELEASE_BML_VERSION "v0.2.0"
#define PIN_RELEASE_BML_COMMIT "8ad2e0b05434f6bd6c47618525982fd56ca5e9f4"

#endif
