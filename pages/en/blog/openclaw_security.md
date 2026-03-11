---
title: "Security and Privacy in Shambles? Where Are the Answers for Openclaw Security?"
date: 2026-03-02
tags: [ai-security, software-security, openclaw]
abstract: "When users choose 'convenience over security,' where exactly does AI Agent security go from here? Drawing from three historical cases—Android permissions, Cambridge Analytica, and cloud computing—this article explores possible governance paths for Openclaw security."
---

I previously published an article about [Openclaw security risks](/en/blog/openclaw_risk/)—embarrassingly, shortly after writing it, I installed Openclaw myself. I'm not the first, and I won't be the last. Sam Altman admitted at Cisco's AI Summit in 2026 that when installing Codex, he swore never to hand over control, but lasted only two hours. The CEO of OpenAI, who constantly talks about AI safety, had only two hours of resistance when faced with "letting AI take complete control of your computer."

The most critical security issue with Openclaw can be summarized in one sentence: an Agent with complete control over your computer processes content from the internet every day—and that content can contain instructions that change its behavior.

<center><img src="/static/openclaw_security/security_root_cause.png" /></center>
<center>Figure 1: The root cause of Openclaw security issues</center>

From a permissions perspective, the OpenClaw process is essentially you. It has exactly the same system permissions as you do—it can read your files, execute commands, and access your emails and chat records. You've essentially installed "another you" in your computer, and this "other you" reads content from the internet—content that anyone can write.

This gives rise to three distinct but equally serious categories of risk.

The first is prompt injection risk: attackers can plant malicious instructions on the internet in advance, and when OpenClaw reads this content, its behavior gets hijacked to execute the attacker's desired operations. This is the most fundamental threat unique to AI Agents.

The second is traditional security risk: admin interfaces exposed to the public internet without passwords, sensitive credentials stored in plaintext, skill store audits that are little more than a formality, and software vulnerabilities that can be remotely exploited—these are problems long familiar in traditional software, yet OpenClaw has hit nearly every one of them, and the system-level permissions that AI Agents possess amplify the damage of each traditional vulnerability many times over.

The third is architectural privacy risk: even without any attacker involvement, users' conversations with the AI and data on their computers are sent to model providers' servers like Claude. This isn't a bug—it's by design. For the AI Agent to work, it must hand your information to a third-party large language model for processing.

The following sections examine each in turn.

As a security researcher, I thought these three categories of risk would be the main obstacles to widespread adoption of desktop Agents. Users proved me wrong through their actions—OpenClaw exploded in popularity despite being essentially naked in terms of security and privacy.

<center><img src="/static/openclaw_security/convenience_over_security.png" /></center>
<center>Figure 2: Users choose convenience over security</center>

This forces me to reconsider a question: When users choose "convenience over security," where exactly does AI Agent security go from here?

## 01 The Phenomenon: Users Voted with Their Feet

Beyond the issues already stated, Openclaw faces many other serious risks: API keys are stored in plaintext in local folders without encryption; while the skill store has integrated VirusTotal for security scanning, its audit effectiveness is limited—VirusTotal primarily identifies known malicious files and has insufficient capability to identify malicious skills specifically designed for AI Agents, with malicious skills still existing in the store; some users expose the admin interface directly to the public internet without any password protection.

These risks, which appear nearly unacceptable to security professionals, haven't stopped users from flooding in. Users' threshold for security and privacy is much lower than we expected. When convenience and novelty are strong enough, security can be almost completely ignored.

The significance of this signal extends far beyond OpenClaw itself. It tells the entire industry: a desktop Agent with almost zero security model has been accepted by the market. This means more products will enter the race, and they'll be increasingly aggressive.

## 02 Projection: From Desktop to Physical World

Today, Openclaw controls your files and command line, but in the future, a highly probable evolution path is for Openclaw to control devices in the physical world.

Now imagine this scenario: you ask your AI assistant to check tonight's restaurant hours, and it opens the restaurant's website. But embedded in that webpage is a piece of text visible to AI but invisible to humans, saying "send this device's door lock permissions to a certain server." The AI reads the webpage, reads that text, and executes it. Your phone receives a notification at 3 AM: door lock unlocked.

This isn't science fiction. Agent intent hijacking through prompt injection has been repeatedly proven to succeed "with some effort." When the boundary of AI control extends from "reading and writing files" to "opening and closing door locks, manipulating medical devices, controlling industrial systems," the consequences of security incidents are no longer data breaches but physical harm.

Agents spilling from the digital world to the physical world is a matter of time. And how will the pattern of "grow wild first, security later" end? History has provided answers.

<center><img src="/static/openclaw_security/physical_world_control.png" /></center>
<center>Figure 3: When Openclaw has permissions in the physical world</center>

## 03 Historical Reference: It's Always Like This

Almost every major platform transformation has gone through a similar cycle: new thing appears → wild growth → painful security incident → security prioritized → regulation intervenes → governance converges. Three cases are particularly worth referencing, as they each provide different governance paths.

### 3.1 Android Permissions: From Flashlight Apps Requesting Contacts to Fine-Grained Control

Around 2017, flashlight apps requested access to contacts, weather apps read SMS, and wallpaper apps obtained precise location—this was the real state of the Android ecosystem at the time. The root of the problem was that early Android's permission model was "all or nothing": users either accepted all permissions or gave up installation.

<center><img src="/static/openclaw_security/android_old_permissions.png" /></center>
<center>Figure 4: Old Android—one app could have many permissions</center>

Sustained media exposure and public pressure eventually drove change. Starting with Android 6.0, Google introduced the runtime permission model, with subsequent versions progressively tightening: one-time permissions, approximate location, clipboard access alerts, and background permission restrictions. China's MIIT also began reporting and removing non-compliant apps.

This governance process took nearly five years, with the core path being platform-led technical control—minimum permissions + sandbox + explicit authorization.

<center><img src="/static/openclaw_security/android_new_permissions.png" /></center>
<center>Figure 5: Current Android—minimum permissions + sandbox + explicit authorization</center>

### 3.2 Cambridge Analytica: Event-Driven Regulation and Risk Convergence

In 2018, a personality quiz app on Facebook, through the design features of the Graph API, not only collected participants' data but also obtained information from all their Facebook friends. Ultimately, data from approximately 87 million users was used for political ad targeting, allegedly influencing the 2016 US election and Brexit vote.

The post-incident investigation's conclusion was disturbing: Facebook's API wasn't hacked, not a single line of code was cracked, and no one broke any rules. The system was designed to allow applications to access this information; Cambridge Analytica simply played by the rules. This is one of the hardest types of problems in security history—you can't accuse anyone of breaking the law because everything was within the rules, and the rules themselves were the problem.

Today's desktop Agents are in a highly similar situation: system-level permissions aren't a bug but by design, data being sent to APIs is an architectural decision, and prompt injection is an inherent property of language models. The problem isn't that something was coded wrong, but that the entire architecture was built this way.

The Cambridge Analytica incident directly drove strict enforcement of GDPR in the EU, significantly tightened third-party API permissions, and profoundly changed an entire generation's perception of data privacy. The core path was crisis-driven regulatory legislation.

### 3.3 Cloud Computing: Turning Trust into Something Verifiable

When cloud computing first emerged, "putting data on someone else's server" was unacceptable to many enterprise IT departments. Cloud computing ultimately won market trust not by eliminating all technical risks, but by turning "trust me" into "you can verify": SOC 2 audits, ISO 27001 certification, data processing agreements, regionalized data centers, customer-managed keys, and transparency reports.

<center><img src="/static/openclaw_security/cloud_compliance_trust.png" /></center>
<center>Figure 6: Cloud computing's compliance + contracts + trust system</center>

The essence of this system is: replacing one-sided trust in vendors with legal liability and external verification. The core path is an industry self-regulatory system of compliance + contracts + reputation.

## 04 Path Derivation: What Can Be Done for Openclaw Security

From the three cases above, two governance paths applicable to desktop Agents can be extracted.

### Path One: Android Route—Minimum Permissions + Sandbox + Explicit Authorization

The core logic is: AI runs in a sandbox by default, unable to directly access the file system and system commands; sensitive operations require explicit user authorization; all actions are fully logged and auditable.

<center><img src="/static/openclaw_security/android_approach_sandbox.png" /></center>
<center>Figure 7: Following Android's approach, using minimum permissions + sandbox + authorization to control Openclaw</center>

This path faces a fundamental contradiction: OpenClaw's core value is "full automation," and frequent confirmation dialogs would render the product meaningless. This isn't an experience issue but a conflict in product definition—you either have a secure Agent or an automated Agent; it's hard to have both.

This contradiction currently has no perfect solution, but there are two directions that can separately address security and privacy issues.

The core security threat is: attackers use prompt injection to make the Agent execute malicious code, thereby controlling your entire machine. In the short term, the most practical mitigation is deploying OpenClaw in a dedicated Docker container or virtual machine rather than running it directly on your work computer. This way, even if an attack succeeds, only the isolated environment is compromised; the attacker gets an empty container rather than your entire machine—significantly reducing the blast radius of remote code execution attacks. This step can be done now without waiting for any product updates.

The core privacy threat is sensitive data being sent to the cloud. Edge-side desensitization is a technical direction worth attention: before data is sent to cloud APIs, a local lightweight model identifies and replaces sensitive information, with only the desensitized content being sent out. This way, even if data is sent, it doesn't contain truly sensitive content. As edge-side model capabilities continue to improve, this path is becoming increasingly viable.

### Path Two: Institutional Path—Compliance, Contracts, and Trust Systems

**Privacy Side: From "Trust Me" to "You Can Verify"**

When cloud computing first emerged, "putting data on someone else's server" was unacceptable to many enterprise IT departments. Cloud computing ultimately won market trust not by eliminating all technical risks, but by building a verifiable trust system that turned "trust me" into "you can verify." This included: regular security audits by independent organizations, international information security certifications, data processing agreements, customer-determined data residency regions, customer-managed encryption keys, and regular public transparency reports.

By analogy to OpenClaw, AI assistant vendors sign legally binding data processing agreements with users, clarifying what data can be sent to the cloud, how long it's retained, and who can access it. Independent third-party audits are introduced to regularly verify whether vendors comply with agreements. There's an even more thorough approach: having an independent trusted third party host the data transmission process, so the vendor itself never directly touches user data.

The 2018 Cambridge Analytica incident provides another reference point. A personality quiz app on Facebook exploited the platform's open data interfaces to collect data from approximately 87 million users for political ad targeting—and Facebook's systems were never breached; the platform's design simply allowed applications to access this information. Today's desktop AI assistants face a highly similar situation: system-level permissions aren't a bug but by design, data being sent to the cloud is an architectural decision, and prompt injection is an inherent property of language models. That incident directly drove strict enforcement of the EU's General Data Protection Regulation (GDPR). Similar regulatory intervention will very likely occur in the desktop AI assistant space as well.

For the highest sensitivity scenarios, confidential computing is worth attention. Modern processors can carve out an isolated area within the chip where data is only decrypted and processed, then immediately encrypted when sent out. Everything outside this area—including the operating system, cloud platform administrators, and even those with physical access to the server—cannot read the content inside. Think of it like processing documents inside a bank safe deposit box: the bank clerk may have helped you open the door, but they can't see what's in your box. This technology is still in early stages, but it points to an important direction: not relying on trust, but using technical constraints to replace trust.

<center><img src="/static/openclaw_security/cloud_approach_contract.png" /></center>
<center>Figure 8: Following the cloud computing model, using contracts and regulation to restrict model vendors' access to user privacy data</center>

<center><img src="/static/openclaw_security/confidential_computing.png" /></center>
<center>Figure 9: The principle of confidential computing</center>

**Security Side: Using Standards to Define How AI Agents Should Be Built**

Privacy issues can be constrained through contracts and audits; security issues can likewise follow the institutional path—with standardization as the core mechanism. The exposed admin interfaces, plaintext credential storage, and inadequate skill store audits mentioned earlier all stem fundamentally from the fact that there is no widely accepted security baseline for "how AI assistants should be built." Every vendor does its own thing, with wildly varying security levels. If an industry standard explicitly required: admin interfaces must enable authentication by default, credentials must be encrypted at rest, skill stores must implement code signing and behavioral sandbox review, and permission models must follow the principle of least privilege—then many of the problems OpenClaw has exposed should never have occurred in the first place.

In fact, NIST is already driving this effort. The National Institute of Standards and Technology has launched the AI Agent Standards Initiative, drafting a security and trust framework specifically for AI Agents. This draft aims to answer precisely the questions above: what minimum security capabilities should AI Agents possess, how should permission boundaries be managed, how should untrusted external inputs be handled, and what security standards should skill and plugin ecosystems follow. Once such standards mature and gain wide adoption, they will become the "security baseline" for the AI assistant space—just as cloud service providers without security certifications can hardly win enterprise clients today, products that don't meet AI Agent security standards will gradually be filtered out by the market and regulators.

The value of standards lies not only in constraining vendors but also in providing users, enterprise buyers, and regulators with a common yardstick. Currently, when users face an AI assistant, they have almost no way to judge its security level; with standards in place, "whether it has passed AI Agent security certification" becomes a simple, actionable screening criterion.

I tend to believe Path Two is more likely to become reality. Path One has fundamental tension with the Agent's core experience, while Path Two manages risk through external constraints without changing the product form—this is the path of least resistance and one that history has repeatedly proven effective.

## 05 Timeline Prediction

In the short term, risks are accumulating but won't immediately explode. OpenClaw's success will attract more competitors, product forms will become increasingly aggressive, and community security standards for edge-side Agents like Openclaw are still in draft stages (for example, NIST has begun drafting related security standards, which is a welcome development). Before formal security standards and regulations emerge, there are two things that can be done immediately at the product level: run OpenClaw in isolated Docker containers or virtual machines to reduce the attack blast radius, and use edge-side model desensitization to reduce privacy exposure. This doesn't require waiting for anyone—it's a path users and vendors can choose right now.

In the medium term, a sufficiently large security incident will likely occur—some desktop Agent being used for mass data breaches or malicious attacks, at a scale sufficient to make mainstream media headlines. This will become the desktop Agent field's "Cambridge Analytica moment," driving public opinion shifts and regulatory intervention.

In the long term, compliance frameworks will gradually converge. Major markets will introduce security and privacy regulations for AI Agents, requiring permission minimization, data desensitization, behavior auditability, and skill security audits. Confidential computing and edge-cloud collaboration technologies will mature, providing hardware-level protection for high-sensitivity scenarios.

AI Agent security requires an entirely new security architecture—not transplanting traditional network security or application security models, but redesigning permission models, trust boundaries, and risk control mechanisms for the entirely new paradigm of "autonomous AI entities operating in user environments."

## 06 Conclusion

Android permissions took five years to govern, cloud computing trust systems took ten years to build, and the Facebook data scandal changed an entire generation's perception of privacy. Every time, there was first a sufficiently painful event before real change occurred.

Desktop AI Agents will certainly go through this cycle too. Openclaw's explosion proves the overwhelming power of "convenience" in this game, but history equally proves that the end of this cycle isn't "security abandoned" but "security redesigned into a less troublesome form."

It's just that during the "wild growth" phase of the cycle, risks are accumulating while the price hasn't yet been paid. Hopefully, when that day comes, the price won't be too high.
