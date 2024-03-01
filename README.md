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
The Fujisaki-Okamoto transformation ("the transformation" in subsequent mentions) is a generic transformation that takes an IND-CPA secure public-key cryptosystem and outputs a IND-CCA secure public-key cryptosystem (under the random oracle assumption).

The inputs to the transformation are as follows:

- An IND-CPA secure public-key cryptosystem `INDCPA.KeyGen`, `INDCPA.Enc`, `INDCPA.Dec`. Note that for the PKCS to be IND-CPA, encryption must be probabilistic, so `INDCPA.Enc` takes as input a "coin" (such as a seed to a PRG)
- An IND-CPA secure symmetric-key cryptosystem `SKCS.Enc` and `SKCS.Dec`
- A hash function $G: \mathcal{M}^{\text{asym}} \rightarrow \mathcal{K}^{\text{sym}}$ that hashes a message from the PKCS into a key for the SKCS
- A second hash function $H: \mathcal{B}^\ast \times \mathcal{B}^\ast \rightarrow \text{Coin}^\text{asym}$, which hashes bitstreams into the some seed that can be fed into `PKCS.Enc` as the source of randomness

The transformed PKCS, which we will call "hybrid", consists of three routines: `INDCCA.KeyGen`, `INDCCA.Enc`, `INDCCA.Dec`. Among them, `INDCCA.KeyGen` is identical to `INDCPA.KeyGen`.

The message space to `INDCCA.Enc` is the message space of the symmetric cipher. It remains to find a way to get a symmetric key, commit to that key, and then obscure the key. To get a symmetric key, we use the hash function $G$ on a randomly sampled message from the IND-CPA PKCS' message space. This gives us the first half of the routine:

```rust
func encrypt(m: SymMessage) -> _ {  // we will discuss the output later
    let sigma: AsymMessage = AsymMessage::sample();
    let key: SymKey = hash_g(&sigma);
    let c1 = Sym::encrypt(key, m);

    todo!("The second half");
}
```

The second half of the ciphertext is constructed to encrypt and provide integrity for $\sigma$, which is the source material for the symmetric key. The encryption is done using the PKCS' encryption, with the source of entropy being a hash of both $\sigma$ and $c_1$:

```rust
fn encrypt<G, H>(m: SymMessage, pk: PublicKey) -> (SymMessage, AsymMessage) {
    let sigma: AsymMessage = AsymMessage::sample();
    let key: SymKey = hash_g(&sigma);
    let c1 = Sym::encrypt(key, m);

    let h = hash_h(sigma, c1);
    let c2 = Asym::encrypt(pk, sigma, h);

    return (c1, c2)
}
```

The decryption routine is a reverse of the encryption routine:

```rust
fn decrypt(
    c: (SymCiphertext, AsymCiphertext),
    pk: AsymPublicKey,
    sk: AsymSecretKey) {
    let (c1, c2) = c;
    let sigma = Asym::decrypt(sk, c2);
    // NOTE: need to check is sigma is a valid PKCS' message
    let hash = hash_h(sigma, c2);
    let c2_hat = Asym::encrypt(pk, sigma, h);
    assert_eq!(c2_hat, c2);
    let symkey = hash_g(sigma);
    return Sym::decrypt(symkey, c1)
}
```

## Intuition for security
One way I think about how IND-CPA secure components can be assembled into IND-CCA secure cryptosystem is by placing checks such that dishonest ciphertexts, generated without knowing the public key and the underlying plaintext, will always be rejected (or be accepted only with negligible advantage). If such rejection mechanism is possible, then the decryption oracle becomes completely useless to the adversary as it will not be able to learn anything that it doesn't already have under the IND-CPA assumption.

For example, in this FO transform, the "re-encryption check" uses $h$, which must be a hash of both $\sigma$ and $c_1$. If not (aka $h = H(\sigma)$), then after $\mathcal{A}_\text{CCA}$ obtains the encryption $(c_1, c_2)$ of some plaintext query $m$, it can re-used $c_2$, but re-generate arbitrary value for $c_1$. A decryption query $(c_1^\prime, c_2)$ where $c_1^\prime$ is dishonest, will be accepted and decrypted, making the hybrid decryption oracle a decryption oracle for the symmetric cipher, and since the symmetric cipher is not IND-CCA, it will be broken.