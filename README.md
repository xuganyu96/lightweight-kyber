# 快速入门
```bash
cd kyber-ref
make
./test_kyber512-ascon
```

如果在 Apple Silicon 上编译 speed 测试，则需要修改 `cpucycles.h` 让编译器使用 ARM 的编汇语言

# 轻量化 Kyber
基于格的密钥封装机制 Kyber 使用了魔改的藤崎-冈本变化以达成 IND-CCA 安全，所以需要一些对称密码的部件。原作者的标准实现采取了两套对称密码的组合：被 NIST 标准化的组合使用基于 Keccak 的 XOF 和哈希函数，另一组【90年代 Kyber】则使用 AES-256 和 SHA-2。考虑到嵌入式应用的场景，Keccak 的内存用量和计算速度都有很大的改进空间。

藤崎-冈本变化的安全证明只要对称密码的部件达到最低的安全水准，加上 Kyber 的参考实现也很给力的给出了合理的抽象化，这个项目将尝试用 NIST 轻量化密码竞赛的获胜算法 ASCON 替换 Kyber 参考实现里的对称密码部件，并测量内存使用和计算的速度。

## 对称密码的使用场景
Kyber 先实现一个 IND-CPA 的封装机制（记作 `CPA.KeyGen`, `CPA.Enc`, `CPA.Dec`），然后加上藤崎-冈本变化。对称密码在 IND-CPA 的实现和 IND-CCA 的实现中都有应用。

哈希函数 $G: \mathcal{B}^\ast \rightarrow \mathcal{B}^{32} \times \mathcal{B}^{32}$：
1. 生成两个32字节的种子 $\rho$, $\sigma$。其中 $\rho$ 用来生成随机生成 $A \in R_q^{k \times k}$，而 $\sigma$ 用来随机生成 $\mathbf{s} \in \chi_s^k$ 和 $\mathbf{e} \in \chi_e^k$

哈希函数 $H: \mathcal{B}^\ast \rightarrow \mathcal{B}^{32}$
1. 哈希 IND-CPA 的公钥
2. 哈希被封装的密钥的原材料 $m \leftarrow H(m)$

伪随机函数 $\text{PRF}: \mathcal{B}^{32} \times \mathcal{B} \rightarrow \mathcal{B}^\ast$
1. 随机生成密钥 $\mathbf{s}, \mathbf{e}$ 中每一个多项式的系数
2. 加密过程中，生成临时秘密 $\mathbf{r} \in \chi_s^k, \mathbf{e}_1 \in \chi_e^k, \mathbf{e}_2 \in \chi_e$ 中每一个多项式的系数

可扩展输出函数 $\text{XOF}: \mathcal{B}^\ast \times \mathcal{B} \times \mathcal{B} \rightarrow \mathcal{B}^\ast$
1. 随机生成矩阵 $A \in R_q^{k \times k}$ 中每一个多项式 $A_{i, j} \in R_q$ 的系数（在 NTT 领域内）

密钥派生函数 $\text{KDF}$
1. 被 `CPA.Enc` 加密的密文 $m$ 并不是最终的共享密钥，而是被输入到一个 KDF 中生成共享的密钥