#include <stdio.h>
#include <string.h>
#include "asconxof/api.h"
#include "asconxof/ascon.h"
#include "asconxof/constants.h"
#include "asconxof/permutations.h"
#include "asconxof/word.h"

#define KYBER_SYMBYTES 32
#define KYBER_SSBYTES 32
#define XOF_BLOCKBYTES ASCON_HASH_RATE 

void printhex(uint8_t *bytes, size_t bytelen) {
    printf("0x");
    for (size_t i = 0; i < bytelen; i++) {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

/**
 * 256-bit hash
 */
void hash_h(uint8_t out[32], const uint8_t *in, size_t inlen) {
    ascon_state_t xof_state;
    ascon_inithash(&xof_state);
    ascon_absorb(&xof_state, in, inlen);
    ascon_squeeze(&xof_state, out, 32);
}

/**
 * 512-bit hash
 */
void hash_g(uint8_t out[64], const uint8_t *in, size_t inlen) {
    ascon_state_t xof_state;
    ascon_inithash(&xof_state);
    ascon_absorb(&xof_state, in, inlen);
    ascon_squeeze(&xof_state, out, 64);
}

/**
 * Absorb seed, x, and y into the XOF state
 */
void xof_absorb(
    ascon_state_t *state,
    const uint8_t seed[KYBER_SYMBYTES],
    uint8_t x,
    uint8_t y
) {
    uint8_t buf[KYBER_SYMBYTES + 2];
    memcpy(&buf, &seed, KYBER_SYMBYTES);
    buf[KYBER_SYMBYTES] = x;
    buf[KYBER_SYMBYTES] = y;
    ascon_absorb(state, buf, KYBER_SYMBYTES);
}

/**
 * Imitate ascon_squeeze, but squeezing only fullblocks
 */
void xof_squeezeblocks(
    uint8_t *out,
    size_t nblocks,
    ascon_state_t *state
) {
    P(state, ASCON_HASH_ROUNDS);
    while (nblocks > 0) {
        STORE(out, state->x[0], ASCON_HASH_RATE);
        P(state, ASCON_HASH_ROUNDS);
        nblocks--;
    }
}

/**
 * Directly use ascon_squeeze to get as much output as needed
 */
void prf(
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
void kdf(
    uint8_t *out,
    const uint8_t *in,
    size_t inlen
) {
    ascon_state_t state;
    ascon_inithash(&state);
    ascon_absorb(&state, in, inlen);
    ascon_squeeze(&state, out, KYBER_SSBYTES);
}

int main(int argc, char *argv[]) {
    uint8_t buf[3] = { 0 };
    uint8_t data[2] = { 0xff, 0xff };
    printhex(buf, sizeof(buf));

    memcpy(buf + 1, data, sizeof(data));
    printhex(buf, sizeof(buf));

    return 0;
}
