# Portfolio 

## 技能标签

<!-- 🧩 技术与研究方向标签 -->
<div style="
  display: flex;
  flex-wrap: wrap;
  gap: 0.4em;
  margin-top: 0.8em;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
">

  <span style="
    background: #e8f0fe;
    color: #1a73e8;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">逆向工程</span>

  <span style="
    background: #e0f7ec;
    color: #0c8a46;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">漏洞挖掘</span>

  <span style="
    background: #fff4e5;
    color: #f57c00;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">模糊测试</span>

  <span style="
    background: #f3e5f5;
    color: #6a1b9a;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">协议分析</span>

  <span style="
    background: #e8f5e9;
    color: #2e7d32;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">模型微调</span>

  <span style="
    background: #fce4ec;
    color: #ad1457;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">智能体设计</span>

  <span style="
    background: #fffde7;
    color: #827717;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">基础运维</span>

  <span style="
    background: #ede7f6;
    color: #4527a0;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">软件架构</span>

  <span style="
    background: #f1f8e9;
    color: #558b2f;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">工程开发</span>

  <span style="
    background: #e0f2f1;
    color: #00695c;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">VibeCoding</span>

</div>


## 已公开的代表性工作

我的部分研究工作属于公司内部项目，涉及公司的知识产权，无法公开分享。此处仅列出可公开的具有代表性研究成果。


### 一、漏洞与攻防研究

#### 1. 协议安全
*   [因发现移动通信网络安全问题，被列入GSMA移动安全研究名人堂](https://www.gsma.com/solutions-and-impact/technologies/security/gsma-mobile-security-research-acknowledgements/)。
*   **移动网络的TCP/UDP劫持问题**: [EuroS&P 2025, The Danger of Packet Length Leakage: Off-path TCP/IP Hijacking Attacks Against Wireless and Mobile Networks](https://www.computer.org/csdl/proceedings-article/euros-p/2025/949300a807/29yCCqNEhMc)

#### 2. 人工智能安全
我关注AI时代衍生的新安全问题，并从攻击者视角展开探索：
*   **一种可以精确控制大模型输出任意内容的方法**: [Black Hat USA 2025, Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://blackhat.com/us-25/briefings/schedule/#universal-and-context-independent-triggers-for-precise-control-of-llm-outputs-45099)
*   **AI网页浏览能力所引入的传统安全风险** [Black Hat EU 2025, AI's 'Web Browsing' Into A Gateway For Targeting 1B+ Users](https://blackhat.com/eu-25/briefings/schedule/index.html#ai-searchs-dark-side-how-we-turned-ais-web-browsing-into-a-gateway-for-targeting-1b-users-49085)
*   **一种利用ICC配置文件实现的人类不可见提示注入** [CCS 2025 Poster/Demo, Black-box Attacks on Multimodal Large Language Models through Adversarial ICC Profiles]()

#### 3. 软件与供应链安全
*   **Chromium的n-day漏洞在Electron等环境中如何产生0day攻击效果**: [DEFCON 31, ndays are also 0days: Can hackers launch 0day RCE attack on popular software only with chromium ndays?](https://forum.defcon.org/node/246107)
*   **打破"可信"加密库的神话，揭示广泛使用的密码学库中的供应链风险**: [Black Hat USA 2026, Breaking the Unbreakable: Dismantling the Myth of "Trusted" Cryptographic Libraries](https://blackhat.com/us-26/briefings/schedule/index.html#breaking-the-unbreakable-dismantling-the-myth-of-trusted-cryptographic-libraries-on-demand-only-53162)
*   **针对xz类高隐蔽后门风险的评估框架** [AAAI 2026, An LLM-based Quantitative Framework for Evaluating High-Stealthy Backdoor Risks in OSS Supply Chains]()

### 二、解决方案研发
#### 1. 大模型在安全方向的应用
*   **基于大模型的安全情报系统**: 基于AI实现安全技术情报的自动搜寻、订阅和分析，典型用途包括在安全研究中跟踪安全技术的最新进展，在业务安全场景中跟踪最新的黑灰产攻击手法等，该系统驱动了[玄武Sectoday](https://sectoday.tencent.com/)，[腾讯后量子主题站](https://sectoday.tencent.com/)。
*   **基于LLM的智能语义检索库，以提升漏洞挖掘和代码审计效率**[Black Hat Asia 2026 Arsenal,CodeRetrX: One-Click to Start Your Journey of Agentic Bug Hunting](https://blackhat.com/asia-26/arsenal/schedule/index.html#coderetrx-one-click-to-start-your-journey-of-agentic-bug-hunting-50342)
 [Github](https://github.com/XuanwuAI/CodeRetrX),[Paper]()
*   **基于安全大模型的EDR告警研判机器人，实现海量告警的自动化分析与定性**：
[一种基于安全大模型的EDR告警研判机器人](https://xlab.tencent.com/cn/2024/01/26/edr-alert-analysis-robot/)
#### 2.后量子密码迁移
*   **分析量子计算威胁并研究应对方案，包括密码资产识别、供应链治理等**：[Black Hat MEA 2025, RSA/EC Under Quantum Countdown: Quantum Timeline, Insights on Migration Challenges and Our Open-Source Solutions](https://blackhatmea.com/speaker/guancheng-li)
#### 3. 利用硬件特性辅助代码分析类任务
* **利用 Intel Processor Trace 辅助绕过反调试**：[S&P 2018 Poster/Demo: PT-DBG: Bypass Anti-debugging with Intel Processor Tracing](https://www.ieee-security.org/TC/SP2018/poster-abstracts/oakland2018-paper14-poster-abstract.pdf)
* **基于 Intel Processor Trace 的高效多核执行流记录与重放**：[CCS 2020 Poster/Demo: RIPT — An Efficient Multi-Core Record-Replay System](https://dl.acm.org/doi/10.1145/3372297.3420021)
* **封装 Intel CPU 的硬件追踪技术，为逆向工程师提供高效且易用的程序执行流追踪与分析工具**：[Black Hat USA 2024 Arsenal: LIBIHT — A Cross-Platform Library for Accessing Intel Hardware Trace Features](https://dl.acm.org/doi/10.1145/3372297.3420021) && [SURE 2025: LibIHT — A Hardware-Based Approach to Efficient and Evasion-Resistant Dynamic Binary Analysis](https://sure-workshop.org/accepted-papers/2025/sure25-3.pdf)