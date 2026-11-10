/* csrc/pin/pins.h - the pins of the C build path, in one place.
 * Dev form: the development build's values of internal/toolchain and internal/version (BML, Spinel, Version).
 * Public form (-DSPINELBPF_PUBLIC): the values of internal/toolchain/pin_release.go.
 * A Go test (TestCPinsMatchGo) compares every value here with the Go constants and the submodule gitlinks, so a pin raised in
 * one place and not the other fails the gate instead of passing silently.
 * Policy version and format limit are the bpf-mlir source's own (go/requirements/spec.go); the dev check reads them from the
 * pinned source when a repo is given, and uses these values otherwise. */
#ifndef SPINELBPF_PINS_H
#define SPINELBPF_PINS_H

#define PIN_VERSION "v0.10.0"
#define PIN_SPINEL_COMMIT "086d514d"

#ifndef SPINELBPF_PUBLIC
#define PIN_PUBLIC 0
#define PIN_COMPILER_COMMIT "2bf112303e42e1a176fc8b248948277ef3dfffc0"
#define PIN_MODULE "github.com/yuskesh/bpf-mlir/go"
#define PIN_MODULE_VERSION "v1.19.1-0.20261111223958-2bf112303e42"
#define PIN_BML_COMMIT "065901b" /* prefix of the third_party/bpf-mlir-loader gitlink */
#define PIN_BML_COMMIT_FULL "065901be3bde2e66f0dcef214be53c7f751eca2c" /* the whole gitlink: the 7-digit form is only for text */
#define PIN_POLICY_VERSION 27
#define PIN_MAX_FORMAT 32
#else
#define PIN_PUBLIC 1
#define PIN_COMPILER_VERSION "v1.22.0"
#define PIN_COMPILER_COMMIT "2bf112303e42e1a176fc8b248948277ef3dfffc0"
#define PIN_MODULE "github.com/yuskesh/go-bpf-mlir"
#define PIN_MODULE_VERSION "v0.20.0"
#define PIN_BML_VERSION "v0.1.1"
#define PIN_BML_COMMIT "ad2eafdc77e610ced3d83d2b39dd3c7ae81b88bc"
#define PIN_BML_COMMIT_FULL PIN_BML_COMMIT
#define PIN_POLICY_VERSION 27
#define PIN_MAX_FORMAT 32
#endif

/* The public pins are always present for the test that compares them with pin_release.go, whatever the form. */
#define PIN_RELEASE_COMPILER_VERSION "v1.22.0"
#define PIN_RELEASE_COMPILER_COMMIT "2bf112303e42e1a176fc8b248948277ef3dfffc0"
#define PIN_RELEASE_MODULE "github.com/yuskesh/go-bpf-mlir"
#define PIN_RELEASE_MODULE_VERSION "v0.20.0"
#define PIN_RELEASE_BML_VERSION "v0.1.1"
#define PIN_RELEASE_BML_COMMIT "ad2eafdc77e610ced3d83d2b39dd3c7ae81b88bc"

#endif
