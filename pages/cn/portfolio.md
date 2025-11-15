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

## 当前主要兴趣点

基于我对全栈技术方向的追求，我在多个技术领域（尤其是安全相关的领域）保持着探索和学习的兴趣。以下内容展示了我当前的主要兴趣和日常工作方向。


### 一、自动化发现高价值漏洞  

高价值漏洞的发现一直是高人力成本的工作。而探索如何让漏洞挖掘更自动化、更高效，是我最感兴趣也是做的最久的方向之一。

在大模型出现之前，我主要借鉴软件工程的思路：  
* **漏洞挖掘能力模块化**：将代码分析、行为分析、Fuzz 等关键能力拆解成可复用模块，把漏洞挖掘转化为工程编排任务。  
* **Fuzz 流程模块化**：将种子选取、程序启动、数据输入、反馈跟踪等环节模块化，实现对新目标的Fuzz的快速启动。理念类似 LibAFL，但抽象程度更高。  

这些尝试在自动化上有提升，但工程开发和维护成本高，且与研究员的手工挖掘习惯差异较大，因此算不上成功。  

大模型出现后，我尝试通过微调安全模型进行漏洞挖掘，但受限于模型能力，很难产生突破。过去一年，随着大模型代码理解与 Agent 能力的提升，我和团队开始利用 **Agentic 方法** 自动化挖掘高价值漏洞。  
目前这条思路已取得实际成果：系统已发现数十个高价值漏洞，其中不少具备复杂逻辑，整体水平已接近中等人类专家。我们会继续沿着这个方向深入研究。  


### 二、大模型安全问题研究  

目前，大模型逐渐成为数字世界的心的核心技术基础设施，但其安全研究还处在早期阶段。当前研究多集中在越狱、提示词注入、数据投毒等显性风险。  

我更关注的隐藏在更深层的是**潜在影响更严重、攻击成本更低**的模型级安全问题——类似于传统软件中的“远程代码执行（RCE）”级风险。  

我目前的工作包括两个方面：  
* **模型自身安全性**：关注因模型结构、权重以及训练流程本身导致的一些潜在漏洞。  
* **模型生态安全**：研究大模型在集成、调用和部署过程中的传统安全风险。  

我与团队已经在这个方向上取得一些成果，并会持续投入，探索更多的大模型安全问题和以及相关防护方法。  


### 三、后量子密码与迁移  

业界普遍认为，量子计算有望在 2035 年左右破解经典密码算法。后量子迁移不仅是算法替换问题，更是一项复杂的系统工程，并具有一系列的技术挑战，如：密码资产的发现、供应链的治理、新的工程实践方案（如密码敏捷性、混合加密等）。我在这个方向的重点是与团队一起设计和研发解决方案应对后量子迁移中的挑战，并推动后量子迁移的工程化实施，为后量子时代的的安全做准备。  

### 四、大模型在安全方向的应用
除了在漏洞挖掘上的尝试，我和团队也在致力于设计和研发大模型在其他安全任务上的解决方案，包括供应链治理、情报收集与分析、安全知识工程、安全数据挖掘、告警降噪等。部分工作成果已经实际投入使用。

---

## 已公开的代表性工作

鉴于安全领域的特殊性，一些工作无法公开分享，此处仅列出部分已公开的具有代表性研究成果。


### 一、漏洞与攻防研究

#### 1. 协议安全
*   [因发现移动通信网络安全问题，被列入GSMA移动安全研究名人堂](https://www.gsma.com/solutions-and-impact/technologies/security/gsma-mobile-security-research-acknowledgements/)。
*   **移动网络的TCP/UDP劫持问题**: [EuroS&P 2025, The Danger of Packet Length Leakage: Off-path TCP/IP Hijacking Attacks Against Wireless and Mobile Networks](https://www.computer.org/csdl/proceedings-article/euros-p/2025/949300a807/29yCCqNEhMc)

#### 2. 人工智能安全
我关注AI时代衍生的新安全问题，并从攻击者视角展开探索：
*   **一种可以精确控制大模型输出任意内容的方法**: [Black Hat USA 2025, Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://blackhat.com/us-25/briefings/schedule/#universal-and-context-independent-triggers-for-precise-control-of-llm-outputs-45099)
*   **AI网页浏览能力所引入的传统安全风险** [Black Hat EU 2025, AI's 'Web Browsing' Into A Gateway For Targeting 1B+ Users](https://blackhat.com/eu-25/briefings/schedule/index.html#ai-searchs-dark-side-how-we-turned-ais-web-browsing-into-a-gateway-for-targeting-1b-users-49085)

#### 3. 软件与供应链安全
*   **Chromium的n-day漏洞在Electron等环境中如何产生0day攻击效果**: [DEFCON 31, ndays are also 0days: Can hackers launch 0day RCE attack on popular software only with chromium ndays?](https://forum.defcon.org/node/246107)
*   **针对xz类高隐蔽后门风险的评估框架** [AAAI 2026, An LLM-based Quantitative Framework for Evaluating High-Stealthy Backdoor Risks in OSS Supply Chains]()

### 二、解决方案研发

*   **基于大模型的安全情报系统**: 基于AI实现安全技术情报的自动搜寻、订阅和分析，典型用途包括在安全研究中跟踪安全技术的最新进展，在业务安全场景中跟踪最新的黑灰产攻击手法等，该系统驱动了[玄武Sectoday](https://sectoday.tencent.com/)，[腾讯后量子主题站](https://sectoday.tencent.com/)。
*   **基于LLM的智能语义检索库，以提升漏洞挖掘和代码审计效率**：[Github](https://github.com/XuanwuAI/CodeRetrX),[Paper]()
*   **基于安全大模型的EDR告警研判机器人，实现海量告警的自动化分析与定性**：[一种基于安全大模型的EDR告警研判机器人](https://xlab.tencent.com/cn/2024/01/26/edr-alert-analysis-robot/)
*   **分析量子计算威胁并研究应对方案，包括密码资产识别、供应链治理等**：[Black Hat MEA 2025, RSA/EC Under Quantum Countdown: Quantum Timeline, Insights on Migration Challenges and Our Open-Source Solutions](https://blackhatmea.com/agenda-2025?utm_source=%7C/bin/id&page=2?utm_source=%7C/bin/id&utm_medium=null&utm_campaign=null&utm_content=null)