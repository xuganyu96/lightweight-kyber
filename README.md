# Lightweight Kyber

# Getting started
Compile and run tests:

```bash
cd kyber-ref
make
./test_kyber512-ascon
make speed
./test_speed512-ascon
```

# Performance result

# Ascon XOF
Ascon uses a sponge design with a 300-bit state. Hash functions, XOF, PRF, and KDF can all be implemented using Ascon's XOF.

# Fujisaki-Okamoto transformation