#ifndef SYMMETRIC_H
#define SYMMETRIC_H

#include <stddef.h>
#include <stdint.h>
#include "params.h"

#ifdef KYBER_90S

#include "aes256ctr.h"
#include "sha2.h"

#if (KYBER_SSBYTES != 32)
#error "90s variant of Kyber can only generate keys of length 256 bits"
#endif

typedef aes256ctr_ctx xof_state;

#define kyber_aes256xof_absorb KYBER_NAMESPACE(kyber_aes256xof_absorb)
void kyber_aes256xof_absorb(aes256ctr_ctx *state, const uint8_t seed[32], uint8_t x, uint8_t y);

#define kyber_aes256ctr_prf KYBER_NAMESPACE(kyber_aes256ctr_prf)
void kyber_aes256ctr_prf(uint8_t *out, size_t outlen, const uint8_t key[32], uint8_t nonce);

#define XOF_BLOCKBYTES AES256CTR_BLOCKBYTES

#define hash_h(OUT, IN, INBYTES) sha256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_aes256xof_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) aes256ctr_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_aes256ctr_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) sha256(OUT, IN, INBYTES)

#elif defined KYBER_ASCON
#include "ascon/ascon.h"
#include "ascon/constants.h"

typedef ascon_state_t xof_state;

void asconxof_hash256(uint8_t out[32], const uint8_t *in, size_t inlen);
void asconxof_hash512(uint8_t out[64], const uint8_t *in, size_t inlen);
void kyber_asconxof_absorb(
    ascon_state_t *state,
    const uint8_t seed[KYBER_SYMBYTES],
    uint8_t x,
    uint8_t y
);
void kyber_asconxof_squeezeblocks(
    uint8_t *out,
    size_t nblocks,
    ascon_state_t *state
);
void kyber_asconxof_prf(
    uint8_t *out,
    size_t outlen,
    const uint8_t key[KYBER_SYMBYTES],
    uint8_t nonce
);
void kyber_asconxof_kdf(
    uint8_t *out,
    const uint8_t *in,
    size_t inlen
);

#define XOF_BLOCKBYTES ASCON_HASH_RATE
#define hash_h(OUT, IN, INBYTES) asconxof_hash256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) asconxof_hash512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_asconxof_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) kyber_asconxof_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_asconxof_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) kyber_asconxof_kdf(OUT, IN, INBYTES)

#else

#include "fips202.h"

typedef keccak_state xof_state;

#define kyber_shake128_absorb KYBER_NAMESPACE(kyber_shake128_absorb)
void kyber_shake128_absorb(keccak_state *s,
                           const uint8_t seed[KYBER_SYMBYTES],
                           uint8_t x,
                           uint8_t y);

#define kyber_shake256_prf KYBER_NAMESPACE(kyber_shake256_prf)
void kyber_shake256_prf(uint8_t *out, size_t outlen, const uint8_t key[KYBER_SYMBYTES], uint8_t nonce);

#define XOF_BLOCKBYTES SHAKE128_RATE

#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)

#endif /* KYBER_90S */

#endif /* SYMMETRIC_H */
