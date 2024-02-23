#include <stdio.h>
#include "asconxof/api.h"
#include "asconxof/ascon.h"


void printhex(uint8_t *bytes, size_t bytelen) {
    for (size_t i = 0; i < bytelen; i++) {
        printf("%X", bytes[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    ascon_state_t xof_state;
    ascon_inithash(&xof_state);

    uint8_t inbytes[10] = { 0 };
    size_t inlen = 10;

    uint8_t buf[64] = { 0 };
    size_t buflen = 64;

    ascon_absorb(&xof_state, inbytes, inlen);
    ascon_squeeze(&xof_state, buf, buflen);

    printhex(buf, buflen);

    return 0;
}
