---
title: We Used AI to Discover a Vulnerability in a Zero-Knowledge Proof Library Used by Sam Altman's Project
date: 2025-11-10
abstract: "Our AI-powered automated vulnerability discovery engine has uncovered more than 30 vulnerabilities across various types of important open-source software, nearly half of which pose significant real-world risks (such as RCE). In this article, we’ll share one particularly interesting case: a high-severity vulnerability (CVE-2025-57801, CVSS 8.6) discovered in the zero-knowledge proof library gnark. We’ll also be sharing more intriguing vulnerabilities in the future."
tags: [software-security, vulnerability]
---
**Author: Guancheng Li, Xiaolin Zhang and Yang Yu of Tencent Xuanwu Lab**

Originally published on the [Tencent Xuanwu Lab Blog](https://xlab.tencent.com/cn/2025/11/10/atuin-gnark-crypto-vulns/)

## Blockchain, ZK-Rollup, and gnark

The core characteristic of blockchain technology lies in its decentralized consensus mechanism. However, this also introduces inherent performance bottlenecks: every transaction needs to be broadcast across the entire network and validated by numerous nodes, resulting in slow transaction speeds and high costs.

To address this challenge, the Web3 community has proposed various scaling solutions, among which ZK-Rollup (Zero-Knowledge Rollup) is considered one of the most promising technologies. ZK-Rollup significantly enhances blockchain transaction processing capacity and reduces costs by transferring substantial computation and storage work off-chain while utilizing zero-knowledge proofs to ensure the same level of security as on-chain operations. Therefore, it has become a favored scaling technology for many blockchain projects and cryptocurrency exchanges.

<center><img src='/static/gnark/ZK-Rollup.png'></center>

However, while ZK-Rollup technology is excellent, its implementation has a high technical barrier. To promote its adoption, ConsenSys launched the zero-knowledge proof library gnark in 2020.

ConsenSys was founded by Joseph Lubin, co-founder of Ethereum, and enjoys high visibility in the Web3 community. Products like MetaMask and Infura are from ConsenSys. After gnark's release, besides being used in ConsenSys' own Ethereum Layer 2 network Linea zkEVM, it has also been adopted by many well-known Web3 projects, including Worldcoin (co-founded by Sam Altman) and Binance's BNB Chain.

Since zero-knowledge proofs are the core of ZK-Rollup technology's security, over the past few years, institutions such as the Ethereum Foundation and Worldcoin have commissioned numerous top-tier Web3 security teams to conduct security audits, including Kudelski Security, Sigma Prime, Consensys Diligence, LeastAuthority, and OpenZeppelin. With endorsements from multiple parties, gnark has been widely recognized as highly secure and reliable.

## CVE-2025-57801, a Signature Malleability Vulnerability in gnark

**Atuin Automated Vulnerability Discovery Engine** is an automated vulnerability discovery system developed by Xuanwu Lab based on large language model technology. The vulnerability CVE-2025-57801 discovered by Atuin this time exists in gnark's functional module used to verify EdDSA/ECDSA signatures within circuits. This is a signature malleability vulnerability.

In other words, in the business scenario of ZK-Rollup, if an Operator uses gnark's flawed signature verification circuit, attackers can exploit this vulnerability to compromise the critical step of "verifying whether the transaction initiator's signature is valid." Attackers can construct a forged transaction with the same content but a different signature based on a genuine transaction (for example, user A transferring 1 token to B), and leverage the defective verification logic to make it deemed valid, thereby repeatedly executing the transaction.

<center><img src='/static/gnark/malleability.png'></center>

When the forged transaction is accepted by the Operator and packaged into a batch, the subsequently generated zero-knowledge proof will also treat it as a valid transaction. Ultimately, when the proof passes validation on the main chain, victim A's account may experience unexpected asset transfers, resulting in economic losses.

## A Silver Lining in the Cloud

After discovering this vulnerability, Xuanwu Lab analyzed its actual impact in the open-source ecosystem. Fortunately, we found that most open-source projects depending on gnark have luckily avoided the vulnerability's impact. This is because gnark provides developers with two ways to implement signature verification circuits:

1. **Native Verification**: Directly call gnark's officially packaged high-level API to complete signature verification. The vulnerability discovered this time exists in this implementation.
2. **Non-native Verification**: Utilize gnark's lower-level cryptographic primitives (such as elliptic curve point multiplication, hashing, etc.) for developers to combine and implement signature verification logic themselves.

Coincidentally, gnark's official documentation and tutorials demonstrate how to build ZK-Rollup using the **Non-native Verification** approach. Developers typically follow official examples, so most open-source projects chose to build their own verification logic, inadvertently avoiding the vulnerable Native API.

Therefore, although the vulnerable code has existed in the codebase since 2020 (EdDSA) and 2023 (ECDSA), most related projects, despite using the vulnerable gnark library, will not trigger the vulnerability.

However, our examination of gnark-related projects is limited to open-source projects. Closed-source commercial projects or exchanges may have development teams that chose gnark's **Native Verification API** for development convenience, potentially making them vulnerable to this attack. This is also an important reason we're writing this article. **We recommend that all development teams of closed-source projects based on ZK-Rollup technology check whether they use gnark's Native Verification, and if so, upgrade as soon as possible.**

# References

- gnark Official Security Advisory: [Security Advisories · Consensys/gnark · GitHub](https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj)
- CVE-2025-57801: [NVD - CVE-2025-57801](https://nvd.nist.gov/vuln/detail/CVE-2025-57801)
