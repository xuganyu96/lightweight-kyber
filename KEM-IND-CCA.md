# IND-CCA security in KEM
In Kyber, IND-CCA security (for KEM) is achieved using the "re-encrypt" test described in the Fujisaki-Okamoto transformation: the message is hashed into a coin that serves as the seed in the probabilistic `CPAPKE.Encrypt` routine. At decapsulation, the message is first recovered from the ciphertext, then the coin is recovered from the message, and `CPAPKE.Encrypt` is called again on the recovered message and coin: the message is authenticated if and only if the output matches the input ciphertext:

The authentication pathway:

```
message -> coin -> ciphertext 
    -> recovered message -> recovered coin -> re-encryption
```

**The coin doesn't have to be the source of randomness in CPAPKE.Encrypt; it could also be the key to a message authentication code**. The modified scheme is as follows:

```python
def encapsulate(pk: CPAPKE.PubKey) -> (Ciphertext, SharedSecret):
    # Message is immediately hashed so as to not leak the system's RNG state
    message = random(32)
    message = hash_h(message)

    prekey, tag_key = hash_g(message + hash_h(pk))
    ct = CPAPKE.encrypt(pk, message)  # Use truly random coin
    tag = MAC(key=tag_key).update(message).finalize()

    share = kdf(prekey + hash_h(ct))  # K = H(prekey || H(c))

    return (ct, tag), share

def decapsulate(sk: CPAPKE.SecretKey, ct: Ciphertext) -> SharedSecret:
    pke_ct, tag = ct  # unpack the ciphertext
    m_hat = CPAPKE.decrypt(sk, pke_ct)
    prekey_hat, tag_key_hat = hash_g(m_hat + hash_h(pk))

    assert MAC(key=tag_key_hat).update(m_hat).finalize() == tag, \
        "decapsulation failure"

    share = kdf(prekey_hat + hash_h(pke_ct))
    return share
```

If security is not non-negligibly affected, then this scheme trades ciphertext size (increased by the size of a tag) for faster decapsulation (computes MAC instead of CPAPKE.encrypt).

## Security definition for KEM


## Sequence of games
**Game 0** is the KEM-IND-CCA game described [above](#security-definition-for-kem).

**Game 1** is identical to game 0, except we modify the decapsulation oracle $\mathcal{O}^{D}$.

Recall that to generate an honest encapsulation, the caller needs to call `(prekey, tag_key) = hash_g(m + hash_h(pk))`. Under the random oracle model, upon receiving a decapsulation query (the query has form $(c_q, t_q)$ where $c_q$ is the CPAPKE ciphertext, and $t_q$ is a tag), the decapsulation oracle can check the hash oracle $\mathcal{O}^G$ to see if the hash oracle's tape contains (aka the adversary has previously made hash query) a query $\text{input} = (m \Vert H(\text{pk})), \text{output} = (k_\text{pre}, k_\text{tag})$ such that:

$$
\text{MAC}(k_\text{tag}, m) = t_q
$$

* If there exists such a query, then the decapsulation oracle assumes the query to be honest and uses the data from the hash query to construct the shared secret and return the result to the adversary
* If there is not such a query, then the decapsulation oracle returns error

We categorize decapsulation queries into three types:
- **honest** queries are generated following the correct encapsulation routine, including querying the hash oracle
- **invalid** queries are dishonestly generated, and the tag does not authenticate
- **almost valid** queries are dishonestly generated without querying the hash oracle, but the tag does authenticate
$$
\begin{aligned}
P[\text{wins $G_0$}] &= P[\text{wins $G_0$ } \cap \text{ all decapsulation queries are honest}] \\
&+ P[\text{wins $G_0$ } \cap \text{ at least one dishonest, but no almost valid}] \\
&+ P[\text{wins $G_0$ } \cap \text{ at least one almost valid}] \\
\end{aligned}
$$

When all decapsulation queries are honest, game 0 and game 1 are identical (decryption oracles in both games will always return the correct decapsulation). When all dishonest decapsulation queries are invalid, game 0 and game 1 are identical (decryption oracles in both games will always reject the query). Thus:

$$
\begin{aligned}
P[\text{wins $G_0$}] - P[\text{wins $G_1$}] \\
&= P[\text{wins $G_0$ } \cap \text{ at least one almost valid}] \\
&- P[\text{wins $G_1$ } \cap \text{ at least one almost valid}] \\
&\leq P[\text{at least one almost valid}] - 0 \\
&= P[\text{at least one almost valid}]
\end{aligned}
$$

The other words, difference of advantages between the two game is at most the probability that an adversary can generate ciphertexts without querying the hash oracle