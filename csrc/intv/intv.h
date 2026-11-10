/* intv: checked integers for the C frontend's interval bounds.
 *
 * A value is a sign and an unsigned 128-bit magnitude over the symmetric domain -(2^128 - 1) .. 2^128 - 1. Zero always has the
 * positive sign. Every operation follows Go's math/big on the same operands, and reports overflow (never a wrapped value) when the
 * exact result leaves the domain. An audit of the Go frontend's math/big uses shows every interval value it makes is in the domain.
 *
 * bigint: an unbounded integer for integer literals only (parseRubyInt and the base-10 reading of Spinel's IntText).
 */
#ifndef INTV_H
#define INTV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef unsigned __int128 intv_u128;

typedef struct {
	bool neg;      /* never true when mag == 0 */
	intv_u128 mag;
} intv;

/* Results of the checked operations. */
typedef enum { INTV_OK = 0, INTV_OVERFLOW = 1 } intv_status;

/* The exit code of an internal assertion (a precondition that Go's frontend guarantees, such as a nonzero divisor). */
#define INTV_ASSERT_EXIT 70

intv intv_from_i64(int64_t v);
intv intv_from_u64(uint64_t v);

intv_status intv_add(intv a, intv b, intv *out);
intv_status intv_sub(intv a, intv b, intv *out);
intv_status intv_mul(intv a, intv b, intv *out);
intv intv_neg(intv a);
intv intv_abs(intv a);
intv intv_quo(intv x, intv d);                     /* truncated toward zero; d != 0 */
void intv_divmod(intv x, intv d, intv *q, intv *m); /* Euclidean: 0 <= m < |d|; d != 0 */
intv intv_floor_div(intv x, intv d);               /* interval.go floorDiv; d != 0 */
bool intv_is_pow2_mag(intv d);                      /* interval.go isPow2Mag */
intv_status intv_lsh(intv x, uint64_t n, intv *out);
intv intv_rsh(intv x, uint64_t n);
intv_status intv_and(intv a, intv b, intv *out);
int intv_bitlen(intv x);
bool intv_is_int64(intv x);
bool intv_is_uint64(intv x);
int64_t intv_int64(intv x);   /* Go's Int64: the low 64 bits of |x|, negated when x < 0 */
uint64_t intv_uint64(intv x); /* Go's Uint64: the low 64 bits of |x| */
int intv_sign(intv x);
int intv_cmp(intv a, intv b);
/* Decimal text into buf (at least 41 bytes: a sign and 39 digits). Returns buf. */
char *intv_string(intv x, char *buf);
/* Reads an optional '-' and decimal digits. Returns false on a malformed text or a magnitude >= 2^128. */
bool intv_parse_dec(const char *s, intv *out);

/* The unbounded literal integer (the rules):
 * - zero-initialise a bigint before its first use (bigint x = {0}); it is then zero;
 * - bigint_set_string and bigint_parse_dec free the previous storage first, so a bigint can be reused; on false it is zero;
 * - bigint_parse_ruby_int does the same once a digit part is left after the sign and prefix; with none (for example "0x"), it
 *   returns false and leaves the bigint unchanged;
 * - bigint_free leaves zero; call it once a bigint is no longer used;
 * - zero has n == 0, and l may then be NULL: no code may pass l to a library call (memcpy and the like) when n is 0. */
typedef struct {
	bool neg;
	size_t n;     /* limbs in use; 0 means zero */
	uint32_t *l;  /* little-endian base 2^32 */
} bigint;

void bigint_free(bigint *x);
/* Go's (*big.Int).SetString(s, base) for base 2, 8, 10 or 16: an optional sign, then at least one digit of the base. */
bool bigint_set_string(bigint *x, const char *s, size_t len, int base);
/* The frontend's parseRubyInt (analyze.go): '_' removed, one sign, a prefix, then SetString. */
bool bigint_parse_ruby_int(bigint *x, const char *s, size_t len);
/* new(big.Int).SetString(s, 10), for Spinel's IntText. */
bool bigint_parse_dec(bigint *x, const char *s, size_t len);
int bigint_cmp(const bigint *a, const bigint *b);
void bigint_neg(bigint *x);
/* Decimal text, malloc'd. */
char *bigint_string(const bigint *x);

#endif
