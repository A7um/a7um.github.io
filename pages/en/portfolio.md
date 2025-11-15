# Portfolio

## Skill Tags

<!-- 🧩 Technical and Research Direction Tags -->
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
  ">Reverse Engineering</span>

  <span style="
    background: #e0f7ec;
    color: #0c8a46;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Vulnerability Discovery</span>

  <span style="
    background: #fff4e5;
    color: #f57c00;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Fuzzing</span>

  <span style="
    background: #f3e5f5;
    color: #6a1b9a;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Protocol Analysis</span>

  <span style="
    background: #e8f5e9;
    color: #2e7d32;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Model Fine-tuning</span>

  <span style="
    background: #fce4ec;
    color: #ad1457;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Agent Design</span>

  <span style="
    background: #fffde7;
    color: #827717;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">DevOps</span>

  <span style="
    background: #ede7f6;
    color: #4527a0;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Software Architecture</span>

  <span style="
    background: #f1f8e9;
    color: #558b2f;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Engineering Development</span>

  <span style="
    background: #e0f2f1;
    color: #00695c;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">VibeCoding</span>

</div>

## Current Main Research Interests

As an aspiring full‑stack engineer, I enjoy exploring a wide range of technologies, especially in the field of security. The following reflects both my personal interests and part of my daily work.

### 1. Automated Discovery of High-Value Vulnerabilities

The discovery of high-value vulnerabilities has always been labor-intensive. Exploring how to make vulnerability discovery more automated and efficient is one of my longest-standing and most passionate research directions.

Before the emergence of large language models, I primarily drew inspiration from software engineering approaches:
* **Modularization of Vulnerability Discovery Capabilities**: Breaking down key capabilities such as code analysis, behavior analysis, and fuzzing into reusable modules, transforming vulnerability discovery into an engineering orchestration task.
* **Modularization of Fuzzing Workflows**: Modularizing components like seed selection, program initialization, data input, and feedback tracking to enable quick launch of fuzzing of new targets. The philosophy is similar to LibAFL, but with a higher level of abstraction.

While these attempts improved automation, they incurred high engineering development and maintenance costs and differed significantly from researchers' manual discovery habits, making them less than successful.

After the advent of large language models, I experimented with fine-tuning security models for vulnerability discovery, but the limited model capabilities made breakthroughs difficult. Over the past year, as LLMs' code understanding and agent capabilities have improved, my team and I have begun using **Agentic methods** to automatically discover high-value vulnerabilities.

This approach has yielded practical results: our system has discovered dozens of high-value vulnerabilities, many involving complex logic, with overall performance approaching that of mid-level human experts. We will continue to deepen our research in this direction.

### 2. LLM Security Research

As large language models became core technological infrastructure of digital world, their security research are still in early stages. Current research mostly focuses on visible risks like jailbreaking, prompt injection, and data poisoning.

My focus is on deeper, more hidden model-level security issues with **potentially more severe impacts and lower attack costs**—risks similar to "Remote Code Execution (RCE)" level vulnerabilities in traditional software.

My current work encompasses two aspects:
* **Model Intrinsic Security**: Focusing on potential vulnerabilities arising from model structure, weights, and the training process itself.
* **Model Ecosystem Security**: Researching traditional security risks in the integration, invocation, and deployment of large language models.

My team and I have already achieved results in this direction and will continue to invest in exploring more systematic model security protection methods.

### 3. Post-Quantum Cryptography and Migration

The industry widely believes that quantum computing will be able to break classical cryptographic algorithms around 2035. Post-quantum migration is not just an algorithm replacement problem, but a complex systems engineering challenge with a series of technical hurdles, such as: cryptographic asset discovery, supply chain governance, and new engineering practices (such as crypto-agility and hybrid encryption). My focus in this direction is working with my team to design and develop solutions to address post-quantum migration challenges and promote the industrialized implementation of post-quantum migration, preparing for security in the post-quantum era.

### 4. LLM Applications in Security
Beyond attempts in vulnerability discovery, my team and I are also committed to designing and developing LLM solutions for other security tasks, including supply chain governance, intelligence collection and analysis, security knowledge engineering, security data mining, and alert noise reduction. Some of these solutions have been deployed in production.

---

## Public Representative Work

 Given the special nature of the security field, some work cannot be publicly disclosed. Here I list only selected representative public research achievements.

### 1. Vulnerability and Attack/Defense Research

#### 1. Protocol Security
*   [Listed in the GSMA Mobile Security Research Hall of Fame for discovering mobile network security issues](https://www.gsma.com/solutions-and-impact/technologies/security/gsma-mobile-security-research-acknowledgements/).
*   **TCP/UDP Hijacking Issues in Mobile Networks**: [EuroS&P 2025, The Danger of Packet Length Leakage: Off-path TCP/IP Hijacking Attacks Against Wireless and Mobile Networks](https://www.computer.org/csdl/proceedings-article/euros-p/2025/949300a807/29yCCqNEhMc)

#### 2. Artificial Intelligence Security
I focus on new security issues emerging in the AI era and explore them from an attacker's perspective:
*   **A Method to Precisely Control LLM Output for Arbitrary Content**: [Black Hat USA 2025, Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://blackhat.com/us-25/briefings/schedule/#universal-and-context-independent-triggers-for-precise-control-of-llm-outputs-45099)
*   **Traditional Security Risks Introduced by AI's Web Browsing Capabilities**: [Black Hat EU 2025, AI's 'Web Browsing' Into A Gateway For Targeting 1B+ Users](https://blackhat.com/eu-25/briefings/schedule/index.html#ai-searchs-dark-side-how-we-turned-ais-web-browsing-into-a-gateway-for-targeting-1b-users-49085)

#### 3. Software & Supply Chain Security
*   **How Chromium N-day Vulnerabilities Can Produce 0-day Attack Effects in Environments Like Electron**: [DEFCON 31, ndays are also 0days: Can hackers launch 0day RCE attack on popular software only with chromium ndays?](https://forum.defcon.org/node/246107)
*   **Assessment Framework for xz-type High-Stealth Backdoor Risks**: [AAAI 2026, An LLM-based Quantitative Framework for Evaluating High-Stealthy Backdoor Risks in OSS Supply Chains]()

### 2. Solution Development

*   **LLM-based Security Intelligence System**: AI-driven automatic search, subscription, and analysis of security technical intelligence. Typical applications include tracking the latest advances in security technology for security research, and tracking the latest black/gray market attack methods in business security scenarios. This system powers [Xuanwu Sectoday](https://sectoday.tencent.com/) and [Tencent's Post-Quantum Cryptography Portal](https://sectoday.tencent.com/).
*   **LLM-based Intelligent Semantic Search Library to Improve Vulnerability Discovery and Code Audit Efficiency**: [Github](https://github.com/XuanwuAI/CodeRetrX),[Paper]()
*   **EDR Alert Analysis Robot Based on Security LLM, Achieving Automated Analysis and Classification of Massive Alerts**: [An EDR Alert Analysis Robot Based on Security LLM](https://xlab.tencent.com/cn/2024/01/26/edr-alert-analysis-robot/)
*   **Analyzing Quantum Computing Threats and Researching Response Solutions, Including Cryptographic Asset Identification and Supply Chain Governance**: [Black Hat MEA 2025, RSA/EC Under Quantum Countdown: Quantum Timeline, Insights on Migration Challenges and Our Open-Source Solutions](https://blackhatmea.com/agenda-2025?utm_source=%7C/bin/id&page=2?utm_source=%7C/bin/id&utm_medium=null&utm_campaign=null&utm_content=null)
