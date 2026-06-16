---
title: "Mythos: As Offense and Defense Enter the Firearms Era, Defense Strategy and the Security Skill Stack Must Be Rewritten"
date: 2026-06-16
tags: [software-security, AI]
abstract: >
  On June 11, 2026, I led an in-depth discussion at AGI Bar in Shanghai with more than thirty security practitioners about the cyber capabilities Mythos demonstrated. When agents can continuously perform asset discovery, vulnerability analysis, PoC/EXP writing, path reasoning, and operational orchestration, how should cybersecurity be rebuilt? This post starts from attack-chain compression, introduces the defender's equation in the AI era, and outlines short-term capabilities such as asset inventory, continuous red team validation and vulnerability scanning, and automated security operations, plus long-term paths toward reachability governance, blast-radius compression, and Agent Skill engineering.
---

On June 11, 2026, I led an in-depth discussion at AGI Bar in Shanghai with more than thirty security practitioners from different backgrounds. Some had spent years in traditional offense and defense; others focused on security operations and enterprise rollout; still others were working on AI agents, model security, and automated red/blue teams.

The starting point was the cyber capability Mythos demonstrated: when agents can continuously perform asset discovery, vulnerability analysis, PoC/EXP writing, path reasoning, and operational orchestration, how should cybersecurity be rebuilt? How should the talent structure of security teams change?

This post is my synthesis of that discussion and a further extrapolation from it.

Mythos here is less a single model than a signal: AI agents are turning attack from a human-driven professional workflow into a model-driven continuous operation. Cyber offense and defense are also moving from the cold-weapons era into the firearms era.

The security industry is not short of correct answers. Secure by design, default deny, least privilege, strong identity, workload identity, and micro-segmentation have long been validated by the most advanced organizations. Together they point to one thing: security should not forever stand behind systems patching holes—it should become a default property of products, platforms, and architecture wherever possible.

The real problem is that correct answers are often expensive.

What is expensive is not product price, but architectural capability, engineering discipline, and organizational coordination. To make security a default property, enterprises must rebuild identity, networking, permissions, service invocation, development workflows, and operational habits. Security teams cannot appear only before and after launch; they must enter earlier architecture and platform decisions.

So the security mainline most enterprises actually run is still SOC, vulnerability management, compliance checks, attack-defense exercises, incident response, and internal red/blue where conditions allow. That system is not wrong. It is the security engineering reality most organizations can sustain amid historical baggage, organizational resistance, and architectural constraints.

But AI agents are changing the premise of that reality: the cost for attackers to discover issues, validate them, rewrite PoCs/EXPs, plan paths, and orchestrate actions is falling. If defenders still plan mainly around "discover faster, respond faster, patch faster," they will increasingly look like they are racing machines for time.

That is why the security defense equation must be rewritten in the AI agent era.

<!--more-->

## I. AI Changes the Entire Attack Chain

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-01-attack-chain-compression.png' /></center>
<center>Figure 1: AI agents can effectively speed up asset discovery, vulnerability analysis, exploit development, lateral movement, and related processes.</center>

AI's enhancement on the attack side is not merely "finding bugs faster."

It compresses the entire chain:

| Phase | Traditional pace | AI agent era pace |
|------|------------------|-------------------|
| Recon | Manual port scans, subdomain enumeration, asset cleanup | Models continuously discover endpoints, shadow APIs, exposed credentials |
| Vulnerability discovery | Manual fuzzing, code review, environment tuning | Models read code, generate candidate bugs, rank exploit value |
| Exploit development | Hand-built payloads, trial and error | Automatic PoC adaptation, iterative exploit refinement |
| Lateral movement | Red team members plan paths and inspect permissions | Multiple agents coordinate to identify high-value systems and identity paths |
| Evasion and counter-detection | Manual AV/EDR rule evasion | Automatic variant generation, feedback testing, continued rewriting |
| Command and control | Humans plan operations | Agents take on an increasing share of operational orchestration |

For exposed credentials, known vulnerabilities, misconfigurations, and scriptable entry points, first contact and exploitation attempts may be compressed to minutes—but patching, isolation, and business-side remediation still run into change windows, production risk, and approval workflows.

This means AI does not make every attack instant. It continuously lowers attackers' marginal cost. Complex internal networks, strong identity, MFA, business semantics, and human approval still create friction—but the room for defenders to rely solely on response speed to buy a time advantage is indeed shrinking.

So the question is not "do we still need a SOC." Of course we do.

The question is: SOCs will increasingly look like operating systems built from data pipelines, detection engineering, automated orchestration, case management, and human approval; red/blue outcomes will become more purple-team-like and continuously validated. What ultimately caps risk will return to more fundamental questions: can attackers reach critical paths, and how large is the blast radius after they do?

---

## II. The Defense Equation: From Racing Time to Controlling Paths

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-02-defender-equation-levers.png' /></center>
<center>Figure 2: How reachability, blast radius, and exposure time window relate in the defender's equation for the AI era.</center>

If you treat security budget as a resource allocation problem, the question in the AI era is not which product is most advanced, but which variables defenders can still truly control.

A semi-quantitative ranking model can express it this way:

> **Defender's Equation in the AI era**
>
> **E[L]{expected loss} ≈ D(t){vulnerability/entry discovery rate} · P_e{exploitability probability} · P_reach{reachability} · B{blast radius} · T_e{exposure time window}**

| Variable | Meaning | Change in the AI agent era | Mainly influenced by |
|------|------|---------------------|--------------|
| **D(t)** | Vulnerabilities and entry points attackers can discover per unit time | Rising fast. Automated discovery makes targets that were once "not worth attacking" worth attacking | Attackers lead; defenders can partially get ahead |
| **P_e** | Whether a discovered issue is exploitable in a specific deployment | Rising. Exploit adaptation, validation, and reproduction costs fall | Both sides |
| **P_reach** | Whether a compromised component can reach a critical path | Becomes one of the defender's most important battlegrounds | Defenders lead |
| **B** | Value and scope reachable once a foothold is established | Can be significantly compressed | Defenders lead |
| **T_e** | Exposure time window; detection and containment time window | Still important, but leverage from MTTR alone declines | Defenders lead |

Much of traditional security operations revolved around **T_e (exposure time window)**: patch SLAs, MTTR, alert response, emergency handling, vulnerability prioritization, and red/blue remediation loops all essentially answered one question:

> Can I close the window before the attacker causes harm through a vulnerability or phishing?

That question still matters, but it is no longer enough. When AI compresses the chain from discovery to exploitation to lateral movement to data access, cutting MTTR from four hours to one hour is valuable—but it may not change final loss.

The new high-leverage questions should become:

> Even if they discover it, can they get in?  
> Even if they get in, can they move laterally?  
> Even if they move laterally, can they get something truly valuable?

That is a shift in focus from **T_e (exposure time window)** to **P_reach (reachability)** and **B (blast radius)**.

But there is an easily overlooked connection: shifting from **T_e (exposure time window)** to **P_reach (reachability)** and **B (blast radius)** does not mean operations no longer matter. It means operations must become a feedback system for structural governance.

SOC, red/blue, vulnerability management, and incident response used to focus on "find the problem and handle it quickly." In the AI agent era, they must also continuously feed real attack paths, real false positives, real handling experience, and real business constraints back into long-term governance of identity, networking, permissions, data, and development workflows.

In other words, automation is not a substitute for long-term structural change—it is the sensor, actuator, and learning system for that change. Without automation, enterprises struggle to continuously see their own **P_reach (reachability)** and **B (blast radius)**; without **P_reach** and **B** governance, automation merely handles the same alerts faster.

---

## III. The Real Levers: Reachability and Blast Radius

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-03-reachability-blast-radius.png' /></center>
<center>Figure 3: Reducing attack reachability and blast radius through default deny, least privilege, and micro-segmentation.</center>

**P_reach (reachability)**

A vulnerability existing does not mean an attacker can exploit it; being able to exploit it does not mean reaching critical business; reaching one point does not mean walking through the internal network to core data, identity systems, and production control planes.

That is the value of micro-segmentation, default deny, workload identity, short-lived credentials, and service-to-service mTLS. They reduce not alert volume, but the paths attackers can take.

More industrially, these capabilities include short-lived, fine-grained, revocable access credentials—cloud IAM roles, OIDC/OAuth scopes, JIT/JEA, SPIFFE/SPIRE SVIDs, and service mesh mTLS. Attackers cannot bypass a path that does not exist. AI can help attackers discover vulnerabilities faster, write exploits, and plan lateral movement—but if paths are cut, high attack efficiency still only spins locally.

**B (blast radius)**

A more realistic assumption in the AI era is that some footholds will be compromised. The real question is what can be touched afterward.

So the second long-term lever is making every foothold "not worth much":

- Business systems should not hold data they should not hold;
- API tokens, service accounts, and CI/CD credentials should be re-reviewed under least privilege;
- Workloads should be short-lived where possible, with externalized state that can be destroyed and replaced;
- One compromised account should not naturally mean a whole set of systems falls;
- Critical actions—deleting databases, exporting data, changing permissions, releasing builds, accessing key-management systems—should not rely on a single identity judgment alone.

If P_reach (reachability) answers "can the attacker get there," B (blast radius) answers "once there, is it worth it?"

This is the most important long-term direction.

It is also the hardest.

---

## IV. The Hard Part Is Not Understanding, but Organizational Capability

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-04-organizational-friction.png' /></center>
<center>Figure 4: Zero trust and micro-segmentation face architectural, organizational, cost, and ROI-expression resistance.</center>

From the defender's equation, P_reach (reachability) and B (blast radius) are the long-term levers most worth investing in during the AI agent era. Logically, enterprises should move more decisively toward zero trust, micro-segmentation, short-lived compute, least privilege, and data minimization—making security a default system property.

But the difficulty of this path is not the idea. It is the transformation itself.

It requires enterprises to re-understand their own systems:

- Which services should access which services;
- Which calls are business-necessary and which are historical residue;
- Which identities have held excessive permissions for too long;
- Which data should never have entered production;
- Which applications can be refactored into stateless or short-lived forms;
- How these changes affect release, observability, audit, rollback, and incident handling.

Such transformation is rarely something security teams can push through alone. It runs into several kinds of resistance:

- **Architectural resistance**: legacy systems, hybrid cloud, dedicated lines, historical network segments, and implicit dependencies—no one dares cut lightly.
- **Organizational resistance**: when security proposes "default deny," business teams hear "production may break."
- **Cost resistance**: real micro-segmentation and zero trust cost not software licenses, but long-term mapping, pilots, gradual rollout, rollback, and operations.
- **Difficulty expressing ROI**: it reduces future risk, but budgets often flow more easily to projects with immediate dashboards.

So the first contradiction in AI-era defense building is:

> Long term, structural transformation matters most; short term, automation is what lands most easily.

Most enterprises will not start with "enterprise-wide zero trust." The more realistic path is to introduce AI along existing security mainlines first—build asset inventory, continuous red team validation and vulnerability scanning, and automated security operations—then use that automation to push long-term reachability and blast-radius governance.

---

## V. Capabilities You Can Build in the Short Term

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-05-see-validate-respond-loop.png' /></center>
<center>Figure 5: AI defense building through asset inventory, continuous red team validation and vulnerability scanning, and automated security operations.</center>

Asset inventory, continuous red team validation and vulnerability scanning, and automated security operations—these are easily conflated, but they solve three different problems.

**Asset inventory** answers: what do I have, where is it exposed, who owns it, and what systems, code, identities, and data does it connect to? Its output is a continuously updated asset and exposure map.

**Continuous red team validation and vulnerability scanning** answers: among these exposures, which can actually be exploited; after exploitation, can a path form; can that path ultimately reach critical business, core data, or high-privilege identity? Its output is not an asset inventory, but validated attack paths and remediation priorities.

**Automated security operations** answers: when something abnormal has already happened, can I use data and process to quickly complete correlation analysis, impact assessment, remediation recommendations, human approval, and post-incident closure? Its output is an observable, authorizable, rollback-capable response pipeline.

The first step gets enterprises out of "we do not even know what we have." The second lets enterprises run exploitability and impact ahead of attackers. The third shortens T_e (exposure time window)—while acknowledging that high-risk remediation still needs human approval and fallback.

### Step 1: Asset Inventory

The first kilometer of enterprise security is still assets.

Many enterprises are not unaware they should pursue zero trust—they simply cannot answer: "What assets do I actually expose externally?" "Which domains still point to old systems?" "Which APIs have no owner?" "Which cloud resources were opened temporarily and never closed?"

This is where AI can add value first: building an asset and exposure map.

More precisely, it must connect asset clues scattered across systems, external exposure, and internal ownership chains:

- Aggregate asset clues from cloud inventory, DNS, certificates, WAF, traffic logs, code repositories, CI/CD, and ticketing systems;
- Automatically identify shadow APIs, abandoned domains, exposed admin consoles, test environments, and temporarily opened ports;
- Link external exposure to internal owners, business systems, code repositories, and deployment environments;
- Rank asset risk so security teams handle the entries attackers are most likely to reach first;
- Continuously monitor new exposure instead of doing an annual inventory once a year.

This path may not immediately solve east-west lateral movement, but it first reduces attacker entry count and turns "what I have, where it is exposed, who owns it" into a continuously updated fact.

### Step 2: Continuous Red Team Validation and Vulnerability Scanning

If attackers can use AI to automatically discover assets, analyze vulnerabilities, and adapt exploitation, defenders should use AI to do the same to themselves first.

The difference is that defenders have more context: code, architecture, logs, configuration, deployment environment, asset relationships, and business priority.

This step can be understood more directly as using AI for the large volume of standardized, procedural work that used to happen in red/blue exercises.

AI-driven automated penetration is already strong enough that asset discovery, vulnerability hypothesis, minimal validation, PoC adaptation, path reasoning, and remediation retesting can all be run continuously by agents. It no longer waits for an annual exercise or a temporary heavy red team—it turns red/blue actions into a daily validation pipeline.

- Use AI for attack-surface discovery and asset correlation;
- Use AI for code audit, configuration audit, and dependency vulnerability scanning;
- Use AI to help generate minimal validation cases, detection validation scripts, or controlled PoCs—validated only in authorized environments, sandboxes, or pre-production;
- Use AI to reason paths from external entry points to internal critical assets;
- Use AI to feed findings into DevOps workflows, automatically generating remediation suggestions, test cases, and regression checks;
- Use AI to retest fixes and confirm risk actually converged.

The value of this path is that it does not require zero trust transformation on day one. It first lets AI continuously play "internal attacker" and "validator," exposing where risk is, whether paths can be completed, and whether fixes actually work—then embeds remediation into development and operations workflows.

From the defender's equation, this is really a fight for first mover advantage on D(t) (vulnerability/entry discovery rate) and P_e (exploitability probability): what attackers can discover, defenders discover first; what attackers can exploit, defenders validate first; what attackers can automate, defenders pipeline first.

### Step 3: Automated Security Operations

The SOC will not disappear. It will become more automated, more engineering-driven, and more like the runtime environment for security agents.

Traditional SOCs relied heavily on manual investigation. An alert appears; an analyst checks EDR, reads firewall logs, inspects traffic, finds account login records, asks business owners, then stitches clues into a timeline. That process is slow, but while the attack chain was not fully compressed, it could still run.

In the AI agent era, this must be automated. But the first prerequisite for automation is not the model—it is the data foundation.

Without sufficiently complete, sufficiently clean, mutually linkable data, AI SOC becomes merely "an alert platform that writes better summaries." It can describe alerts more fluently, but cannot reliably judge who an account is, which business a machine belongs to, whether an API reaches core data, whether an action deviates from historical baseline, or whether a remediation will affect production.

So SOC automation must first strengthen the security data foundation. It is not simply ingesting all logs—it must form event graphs, asset graphs, identity graphs, permission graphs, service dependency graphs, and ownership graphs that agents can use:

- **Endpoint data**: EDR, host behavior, processes, files, registry, container runtime, workload identity;
- **Network data**: north-south traffic, east-west traffic, DNS, proxies, WAF, gateways, firewalls, NDR;
- **Cloud data**: cloud audit logs, control-plane operations, object storage access, temporary credentials, cloud security groups and policy changes;
- **Identity data**: account login, MFA, permission changes, token usage, service account behavior;
- **Application data**: business logs, API calls, error codes, critical operations, data export, admin console access;
- **Asset and ownership chains**: asset ownership, business systems, code repositories, owners, deployment environments, data classification;
- **Remediation action data**: action permissions, approval records, execution results, impact scope, and audit logs.

After this data is collected, data engineering, rules, and graph models must first complete entity resolution and correlation; only then can agents query, reason, and generate remediation recommendations on top. Otherwise AI sees isolated logs, not attack paths.

The most realistic near-term value of AI SOC is not "automatically remediate everything," but automating repetitive, time-consuming, context-heavy work first:

- Alert deduplication;
- Alert prioritization;
- IOC enrichment;
- Initial phishing email triage;
- Initial forensics;
- Log backtracking;
- Correlation analysis across endpoint, network, cloud, identity, and application data;
- Mapping vulnerability intelligence to asset impact;
- Detection rule generation and replay;
- Playbook recommendation;
- Remediation recommendations, execution, and post-incident reports.

High-risk remediation still needs human approval. Isolating hosts, disabling accounts, blocking networks, rolling back systems, and actions that affect production should not be fully delegated to autonomous AI in the near term.

---

## VI. Organizational Capability: Writing Operations and Offense-Defense Experience into Agents

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-06-agent-skill-factory.png' /></center>
<center>Figure 6: Security teams engineering SOC, red/blue, and purple-team experience into executable Agent Skills.</center>

There is an important distinction here:

> AI does not automatically possess security wisdom. People distill their judgment processes into workflows that AI can execute, inspect, and authorize.

This also explains why talent structure will change. In the past, the scarcest people in security teams were those who could personally run complex workflows end to end: querying logs, stitching timelines, judging false positives, writing reports, retesting; or manually doing asset probing, vulnerability validation, path reasoning, detection evasion, and attack-defense retrospectives. Those abilities still matter, but higher leverage will fall on another kind of person: those who can break experience into SOPs, tool invocations, permission boundaries, validation standards, and rollback conditions.

Much security capability used to depend on tacit human knowledge: seeing an alert and knowing which tables to check first; seeing abnormal traffic and judging false positive versus lateral movement; seeing a vulnerability and estimating real exploitability in current assets. That experience used to live only in people's heads, or scattered across retrospective documents, chat logs, and veteran habits.

But it is important to emphasize: it is not only SOC that needs SOP / Skill formalization.

SOC should codify alert triage, log backtracking, impact analysis, remediation approval, and retrospective reporting; red team should codify asset probing, vulnerability hypotheses, controlled validation, permission path reasoning, and attack-chain retrospectives; blue team should codify detection rule generation, rule replay, evidence standards, false-positive attribution, and response playbooks; purple team and continuous validation should codify workflows for "is this attack path reachable, does this detection rule work, did remediation actually converge."

The valuable part of these capabilities is not erased by AI—it is engineered: judgment basis, evidence standards, branch conditions, exception handling, escalation rules, permission boundaries, and validation standards become process assets agents can invoke.

Therefore SOP / runbook / playbook is not "write a few documents." They should be further engineered into Agent Skills or executable capability packs: tool invocation, inputs and outputs, permission boundaries, checkpoints, rollback conditions, and evaluation examples. They should be version-controlled like code, tested like detection rules, authorized like production changes, and rollback-capable like emergency workflows.

Security teams need AI-native security automation capability: the ability to break SOC, red, blue, purple, and security work inside development and operations workflows into playbooks / Skills, connect tools and data, design permission boundaries, build evaluation sets, and continuously observe agent output quality.

Such people need to:

- See the system: from business goals, tech stack, attack surface, identity relationships, and adversary capability, draw offense-defense reasoning maps.
- Write SOPs: break human tacit knowledge and judgment into steps, branches, inputs, outputs, evidence standards, exceptions, and escalation conditions.
- Write Skills: turn SOPs into tool chains, context, permission boundaries, checkpoints, and rollback mechanisms agents can execute.
- Build the data foundation: know which endpoint, network, cloud, identity, application, asset, and ownership data agents need for reliable judgment.
- Evaluate outcomes: know when agent conclusions are trustworthy, when human review is needed, and when conservative fallback is mandatory.
- Organize offense-defense loops: connect red findings, blue detection, purple validation, SOC remediation, and DevOps fixes into continuous improvement.
- Explain tradeoffs: explain why resources should go to P_reach (reachability), B (blast radius), T_e (exposure time window), D(t) (vulnerability/entry discovery rate), or P_e (exploitability probability).
- Communicate with the business: explain to leadership "why we need micro-segmentation," not merely "we need zero trust."

The AI era will not eliminate security people. Sample triage, patch diff, crash triage, vulnerability reproduction, PoC adaptation, and alert pre-screening will be greatly accelerated by agents—but high-quality vulnerability research, complex-environment penetration, architectural tradeoffs, and business communication still depend on human judgment.

In other words, the core assets of future security teams are not only people themselves, but also the SOPs, Skills, playbooks, validation sets, permission models, evaluation standards, and data assets those people accumulate. One expert still matters—but a team that can replicate expert experience across a set of agents, then feed agent execution results back into organizational governance, matters more.

For more on where security practitioners should anchor personal value, see [After Claude Mythos: What Keeps Security Practitioners From Becoming Obsolete?](/en/blog/after-claude-mythos-security-practitioners).

---

## VII. A Roadmap for Security Planning

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-07-security-roadmap.png' /></center>
<center>Figure 7: A security planning roadmap from asset mapping and continuous validation to SOC automation and Agent Skills.</center>

If you translate the above into planning order, it can be summarized in four steps.

Point one: build an asset and exposure map, turning "what I have, where it is exposed, who owns it, and what business it affects" into a continuously updated fact.

Point two: connect continuous security validation into DevOps and daily automated red/blue workflows, gradually pipeline attack-surface discovery, vulnerability discovery, controlled validation, path reasoning, remediation recommendations, and regression validation.

Point three: automate SOC workflows, using a more complete data foundation and clearer playbooks to shorten T_e (exposure time window)—while keeping human approval and fallback for high-risk remediation.

Point four: write the judgment methods accumulated in these processes into SOPs and Skills. Alert retrospectives, red/blue exercises, continuous validation, vulnerability remediation, and emergency response should all update these capability packs in return—and further support long-term P_reach (reachability) and B (blast radius) governance: zero trust, micro-segmentation, least privilege, short-lived compute, and data minimization.

In other words, short term you do not skip structural transformation—you first use AI to build asset inventory, continuous red team validation and vulnerability scanning, and automated security operations; long term you use those facts and workflows to push systems toward being harder to reach and less worth compromising.

---

## Closing

<center><img src='/static/mythos-era-attack-defense-evolution/chapter-08-closing-defense-shift.png' /></center>
<center>Figure 8: AI raises the speed of asset inventory, continuous validation, and security operations; people design systems that are harder to reach and harder to move through.</center>

The most dangerous thing about the Mythos era is not that AI is too strong—it is that we are still planning for next-generation attack automation using last-generation security operations rhythm.

Zero trust, micro-segmentation, and least privilege are not new answers. They have always been correct answers—just too heavy, too expensive, and too dependent on organizational capability, so for a long time only engineering-strong companies could push them systematically.

AI agents did not overturn those answers. They put them back on the table. The faster the attack chain, the less room there is to buy time through response alone; the more automated attackers become, the more system reachability and blast radius matter.

The realistic path will not arrive in one step. Most enterprises are more likely to use AI first to build asset inventory, continuous red team validation and vulnerability scanning, and automated security operations—then use the data, SOPs, Skills, and retrospective experience from that process to push zero trust, micro-segmentation, least privilege, and data governance off the long-term backlog.

Human value will also be reassessed in this process. What was most valuable before was people who could get things done well; what becomes more valuable next is people who can explain complex workflows clearly, break them down precisely, write them into SOPs, turn them into Agent Skills, and continuously evaluate whether they actually reduced D(t) (vulnerability/entry discovery rate), T_e (exposure time window), P_reach (reachability), and B (blast radius).

Human experience will not disappear—but it must move from "only in my head" to "security capability the organization and agents can reuse, validate, and iterate."

In one sentence:

> AI is responsible for raising the speed of asset inventory, continuous red team validation and vulnerability scanning, and automated security operations; people are responsible for designing systems that are harder to reach, harder to move through, and less worth compromising, while continuously operating and enhancing automated AI agent systems.

That is where the defense equation truly and importantly must be rewritten in the AI agent era.
