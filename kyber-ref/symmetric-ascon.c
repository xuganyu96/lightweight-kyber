#include <stdint.h>
#include <string.h>
#include "ascon/api.h"
#include "ascon/ascon.h"
#include "ascon/constants.h"
#include "ascon/permutations.h"
#include "ascon/word.h"
#include "params.h"
#include "symmetric.h"

/**
 * 256-bit hash
 */
void asconxof_hash256(uint8_t out[32], const uint8_t *in, size_t inlen) {
  ascon_state_t xof_state;
  ascon_inithash(&xof_state);
  ascon_absorb(&xof_state, in, inlen);
  ascon_squeeze(&xof_state, out, 32);
}

/**
 * 512-bit hash
 */
void asconxof_hash512(uint8_t out[64], const uint8_t *in, size_t inlen) {
  ascon_state_t xof_state;
  ascon_inithash(&xof_state);
  ascon_absorb(&xof_state, in, inlen);
  ascon_squeeze(&xof_state, out, 64);
}

/**
 * Absorb seed, x, and y into the XOF state
 */
void kyber_asconxof_absorb(
  ascon_state_t *state,
  const uint8_t seed[KYBER_SYMBYTES],
  uint8_t x,
  uint8_t y
) {
  uint8_t extseed[KYBER_SYMBYTES + 2];
  memcpy(extseed, seed, KYBER_SYMBYTES);
  extseed[KYBER_SYMBYTES + 0] = x;
  extseed[KYBER_SYMBYTES + 1] = y;
  ascon_inithash(state);
  ascon_absorb(state, extseed, KYBER_SYMBYTES + 2);
}

/**
 * Imitate ascon_squeeze, but squeezing only fullblocks
 */
void kyber_asconxof_squeezeblocks(
  uint8_t *out,
  size_t nblocks,
  ascon_state_t *state
) {
  P(state, ASCON_HASH_ROUNDS);
  while (nblocks > 0) {
    STORE(out, state->x[0], ASCON_HASH_RATE);
    out += ASCON_HASH_RATE;
    P(state, ASCON_HASH_ROUNDS);
    nblocks--;
  }
}

/**
 * Directly use ascon_squeeze to get as much output as needed
 */
void kyber_asconxof_prf(
  uint8_t *out,
  size_t outlen,
  const uint8_t key[KYBER_SYMBYTES],
  uint8_t nonce
) {
  uint8_t seed[KYBER_SYMBYTES + 1];
  seed[0] = nonce;
  memcpy(seed + 1, key, KYBER_SYMBYTES); // TODO: verify pointer arithmetic

  ascon_state_t state;
  ascon_inithash(&state);
  ascon_absorb(&state, seed, KYBER_SYMBYTES + 1);
  ascon_squeeze(&state, out, outlen);
}

/**
 * write KYBER_SSBYTES bytes to "out" based on the input 
 */
void kyber_asconxof_kdf(
  uint8_t *out,
  const uint8_t *in,
  size_t inlen
) {
  ascon_state_t state;
  ascon_inithash(&state);
  ascon_absorb(&state, in, inlen);
  ascon_squeeze(&state, out, KYBER_SSBYTES);
}
