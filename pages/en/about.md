# About Me

Hello, I'm Atum, currently serving as a Researcher at [Tencent's Xuanwu Lab](https://xlab.tencent.com/). [I believe that the underlying logic of technology is interconnected, and I aspire to become a full-stack technical professional](/en/blog/why-and-how-to-be-full-stack/). Mastering a comprehensive technology stack not only provides me with cross-domain perspectives but also gives me broader thinking when designing solutions and deeper insights when discovering vulnerabilities.

My technical research career began with CTF (Capture The Flag) competitions. I was an early member of the [Blue-Lotus](https://ctftime.org/team/1941/) team, and later co-founded the [r3kapig](https://ctftime.org/team/58979) team with friends, serving as its first captain. We qualified for the [DEFCON CTF](https://ctftime.org/ctf/2/) finals for multiple consecutive years. This experience laid a solid foundation for my technical research.

Beyond technology, my greatest interest is reading. I view it as an effective way to trigger thinking—much like how prompts can trigger the chain of thought in large language models. To this end, I have maintained a daily reading habit of approximately 1.5 hours for nearly 3 years, covering philosophy, finance and economics, psychology, and literature. Among these, I have a particular fondness for philosophy, with extensive exploration of both Eastern and Western philosophical traditions. Therefore, [some of my blog content also touches on philosophical topics](/en/tag/philosophy/).

## Personal Tags

<!-- 🔖 Personal Tags -->
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
  ">Amateur Philosopher</span>

  <span style="
    background: #ffe8e8;
    color: #d93025;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Chinese Culture Enthusiast</span>

  <span style="
    background: #fff4e5;
    color: #f57c00;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Amateur Ci Poet</span>

  <span style="
    background: #e0f7fa;
    color: #00796b;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Classical Chinese Reader</span>

  <span style="
    background: #f3e5f5;
    color: #6a1b9a;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Skateboard Commuter</span>

  <span style="
    background: #e8f5e9;
    color: #2e7d32;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Aspiring Full-Stack</span>

  <span style="
    background: #fce4ec;
    color: #ad1457;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Former CTF Player</span>

  <span style="
    background: #eceff1;
    color: #455a64;
    padding: 0.25em 0.75em;
    border-radius: 0.6em;
    font-size: 0.9em;
  ">Not Fond of Writing Papers</span>
</div>

## Links

* Email: lgcpku[AT]gmail.com
* GitHub: https://github.com/a7um
---

## My Research Directions

My research interests focus on security problems that are **wide-impact, high-severity, and systemic** in nature. I aim to tackle these problems with innovative approaches that can raise the overall security baseline. For a list of my public research outputs, please refer to my [portfolio page](/en/portfolio.md).

Currently, my main areas of focus include:

### 1. AI Security

As large language models become a new layer of digital infrastructure, I pay special attention to core security issues that combine low attack cost with potentially large impact, and explore corresponding defenses. My research includes:

* **Model intrinsic security**: structural vulnerabilities introduced by model architectures, weights, or training pipelines. For example, at [Black Hat USA we presented a new attack that can precisely control LLM outputs](https://blackhat.com/us-25/briefings/schedule/#universal-and-context-independent-triggers-for-precise-control-of-llm-outputs-45099).
* **Model ecosystem security**: traditional security risks in the integration, invocation, and deployment of large models. For instance, at [Black Hat Europe we revealed how LLM "web browsing" features can lead to server-side RCE risks due to embedded browser components](https://blackhat.com/eu-25/briefings/schedule/index.html#ai-searchs-dark-side-how-we-turned-ais-web-browsing-into-a-gateway-for-targeting-1b-users-49085).

My team and I will continue to work on long-term security challenges in the era of foundation models.

### 2. Using AI to Automatically Discover Vulnerabilities and Backdoors

The discovery of high-value vulnerabilities has traditionally depended on large amounts of human effort. I have been long interested in how to use AI to improve the automation and intelligence of this process. Our current systems have automatically discovered **50+ high-value vulnerabilities** in widely used open-source software, more than half of which have substantial real-world impact (such as server-side RCE or private-key recovery in cryptographic algorithms). Overall, their capabilities are approaching those of mid-level human experts.  
In parallel, I am actively exploring automated detection of software backdoors and hope to make breakthroughs in this direction in the future.

### 3. Quantum Computing Threats and Post-Quantum Migration

Quantum computing may structurally undermine today's cryptographic systems. Post-quantum migration is a system-wide engineering effort that spans cryptographic asset discovery, supply-chain governance, and engineering practices such as crypto-agility and hybrid encryption. Together with my team, I work on designing practical migration strategies and driving the engineering adoption of post-quantum technologies in real-world environments.
