#include <stdio.h>
#include "asconxof/api.h"
#include "asconxof/ascon.h"
// #include "asconxof/crypto_hash.h"
#include "asconxof/permutations.h"
#include "asconxof/printstate.h"
#include "asconxof/word.h"



int main(int argc, char *argv[]) {
    state_t xof_state;
    ascon_hashinit(&xof_state);

    uint8_t inbytes[10] = { 0 };
    size_t inlen = 10;

    ascon_absorb(&xof_state, inbytes, inlen);

    return 0;
}
