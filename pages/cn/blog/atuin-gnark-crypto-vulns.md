---
title: "我们用AI发现了一个零知识证明库的漏洞，Sam Altman的项目也用了这个库"
date: 2025-11-10
abstract: >
  我们研发的AI自动化漏洞挖掘引擎已经在各种类型的重要开源软件中挖出了30多个漏洞，其中近半数都是具有较高的实际危害（如RCE）。这篇文章将分享一个比较有趣的漏洞:"零知识证明库 gnark 中发现了一个高危漏洞（CVE-2025-57801，CVSS 8.6）"，后续我们也会分享更多有意思的漏洞出来。
tags: [software-security, vulnerability]
---
**Author: Guancheng Li, Xiaolin Zhang and Yang Yu of Tencent Xuanwu Lab**

本文首发于[玄武实验室官方博客](https://xlab.tencent.com/cn/2025/11/10/atuin-gnark-crypto-vulns/)

## 区块链、ZK-Rollup 和 gnark

区块链技术的核心特点在于其去中心化共识机制。然而，这也带来了固有的性能瓶颈：每笔交易都需在全网广播并由大量节点验证，导致交易速度慢且成本高昂。

为解决这一难题，Web3 社区提出了多种扩容方案，其中 ZK-Rollup（零知识卷叠）被认为是最具前景的技术之一。ZK-Rollup 通过将大量的计算和存储工作转移到链下，同时利用零知识证明保证与链上同等级别的安全性，从而极大地提升了区块链的交易处理能力并降低了成本，因此成为众多区块链项目和数字货币交易所青睐的扩容技术。

<center><img src='/static/gnark/ZK-Rollup.png'></center>

然而，ZK-Rollup 技术虽好，但实现的技术门槛较高。为了推动其普及，在 2020 年 ConsenSys 公司推出了零知识证明库 gnark。

ConsenSys 由以太坊的联合创始人 Joseph Lubin 创办，在 Web3 社区有较高知名度。MetaMask、Infura 等都是 ConsenSys 的产品。所以 gnark 发布后，除被用于 ConsenSys 自己的以太坊二层网络 Linea zkEVM 外，也被很多知名 Web3 项目所采用，包括由 Sam Altman 担任联合创始人的 Worldcoin、以及币安的 BNB Chain 等。

由于零知识证明是 ZK-Rollup 技术安全性的核心，所以在过去几年中，以太坊基金会、Worldcoin 等机构委托了众多顶级 Web3 安全团队对其进行安全审计,包括：Kudelski Security、Sigma Prime、Consensys Diligence、LeastAuthority以及OpenZeppelin等。在多方背书下，gnark 被广泛认为是高度安全和可靠的。

## CVE-2025-57801，gnark 签名中的可锻造性漏洞

**阿图因自动化漏洞挖掘引擎**是玄武实验室基于大模型技术研发的一套自动化漏洞挖掘系统。此次阿图因发现的漏洞 CVE-2025-57801 存在于 gnark 库中用于在电路中验证 EdDSA/ECDSA 签名的功能模块。这是一个签名可锻造性（Signature Malleability）漏洞。

也就是说，在 ZK-Rollup 的业务场景中，如果 Operator 使用了 gnark 中存在缺陷的签名验证电路，那么攻击者便可利用此漏洞破坏“验证发起方签名是否合法”这一关键环节。攻击者可以基于一笔真实交易（例如，用户 A 向 B 转账 1 个代币），构造出一笔内容相同但签名不同的伪造交易，并利用有缺陷的验证逻辑使其被判定为有效，从而反复执行该交易。

<center><img src='/static/gnark/malleability.png'></center>

当伪造的交易被 Operator 接受并打包进批次后，后续生成的零知识证明同样会视其为有效交易。最终，当证明在主链上通过验证后，受害者 A 的账户就可能会发生非预期的资产转移，从而造成经济损失。

## 不幸中的万幸

发现此漏洞后，玄武实验室对其在开源生态中的实际影响进行了分析。幸运的是，我们发现大多数依赖 gnark 的开源项目幸运地躲开了该漏洞的影响。这是因为 gnark 为开发者提供了两种实现签名验证电路的方式：

1. **Native Verification**: 直接调用 gnark 官方封装好的高级 API 来完成签名验证。本次发现的漏洞正存在于此实现中。
2. **Non-native Verification**: 利用 gnark 提供的更底层的密码学原语（如椭圆曲线点乘、哈希等），由开发者自行组合实现签名验证逻辑。

而 gnark 的官方文档和教程在演示如何构建 ZK-Rollup 时，凑巧用了 **Non-native Verification** 的方式。而开发者通常会遵循官方示例，因此大多数开源项目选择自行搭建验证逻辑，于是无意中避开了存在漏洞的 Native API。

所以，尽管存在漏洞的代码自 2020 年（EdDSA）和 2023 年（ECDSA）起便已存在于代码库中，所以大部分相关项目虽然用了存在漏洞的 gnark 库，但漏洞并不会被触发。

不过，我们对 gnark 相关项目的检查仅限于开源项目。未开源的商业项目或交易所，其开发团队也可能为了开发的便捷性而选择了 gnark 提供的 **Native Verification API**，从而可能被此漏洞攻击。这也是我们写这篇文章的一个重要原因。**建议所有基于 ZK-Rollup 技术的闭源项目的开发团队都检查一下是否用了 gnark 的 Native Verification，如果用了，抓紧时间升级吧。**

# 参考链接

- gnark 官方漏洞公告：[Security Advisories · Consensys/gnark · GitHub](https://github.com/Consensys/gnark/security/advisories/GHSA-95v9-hv42-pwrj)
- CVE-2025-57801：[NVD - CVE-2025-57801](https://nvd.nist.gov/vuln/detail/CVE-2025-57801)
