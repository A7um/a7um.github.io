---
title: "After Mythos: Seven Trends in Automated Vulnerability Discovery"
date: 2026-07-02
tags: [ai-security, software-security, vulnerability]
abstract: >
  Mythos matters not only because of a model capability jump, but because it turned AI-driven vulnerability discovery into an industry mobilization event. In the post-Mythos era, discovery will keep getting cheaper and mid-hanging bugs will be released quickly. The scarce resources will move elsewhere: repository-level coverage, low-noise validation, patching, disclosure, maintainer capacity, and governance against supply-chain poisoning and change-entry attacks. This article lays out seven trends for the next stage of automated vulnerability discovery.
---

# After Mythos: Seven Trends in Automated Vulnerability Discovery

A few months ago, in [Automated Vulnerability Discovery: Past, Present and Future](/en/blog/ai-vuln-discovery-evolution), I argued that AI-driven vulnerability discovery was moving from "code classification" to "LLMs augmenting traditional tools," and then toward "agentic code auditing." The important question was not whether a model could label a code snippet as vulnerable. The important question was whether it could behave more like a security researcher: actively explore a codebase, call tools, form hypotheses, and validate them.

A few months later, this direction has moved faster than I expected.

After Anthropic released Claude Mythos Preview and launched [Project Glasswing](https://www.anthropic.com/glasswing), AI-driven vulnerability discovery stopped being a niche technical topic inside the security community. It entered the field of view of frontier model labs, critical infrastructure stakeholders, and parts of the governance discussion. Many people read this moment as: Mythos crossed a capability threshold.

I think that is only half right.

The significance of Mythos is not just that the model is stronger. It is that Mythos placed "AI bug hunting" in front of the industry in something close to an industrial form: it can run at scale, produce real results, assist exploit construction, and carry risks that cannot be released without constraints. It made many companies, research groups, open-source communities, and governance actors realize that AI bug hunting is no longer just a paper demo or a handful of teams' engineering experiment. It is becoming a production capability.

In that sense, Mythos is less a single model singularity and more an industry mobilization signal.

This article is not another recap of Mythos itself. It is about what comes after Mythos. My core view is that vulnerability discovery capacity will continue to rise. Low-hanging and mid-hanging bugs will be consumed quickly. After that, the bottleneck will move from "can we find bugs?" to "can we sweep repositories cleanly, validate with low noise, patch, disclose, and help maintainers absorb the output?"

In short: discovery is getting cheaper, while governance is becoming scarce.

<!--more-->

## Prologue: Mythos Is Not a Singularity, but a Mobilization Signal

### The breakout came from capability, scale, and narrative together

The popularity of Mythos cannot be explained by model capability alone.

Anthropic did several things right. First, it ran the system at scale and showed results with enough impact. Second, it connected vulnerability discovery, exploit construction, defensive collaboration, and risk control into one narrative. Third, through Project Glasswing, it tied capability release to controlled delivery, making the event more than a model release.

That matters.

If a team merely says "our model improved by 15% on a benchmark," it rarely changes industry investment. But if a frontier model lab says a model can find long-hidden issues in mainstream operating systems, browsers, and infrastructure software, can help construct exploits, and is risky enough not to be fully released, then the result is no longer just a technical artifact. It becomes a shared industry anxiety.

Mythos' influence comes from this combination: capability demonstration, scaled operation, risk narrative, and ecosystem mobilization.

### Mythos changed the slope of industry investment

Automated vulnerability discovery did not begin with Mythos. Before Mythos, a small number of teams were already working on LLM-assisted auditing, agentic security review, automated validation, and large-scale repository scanning. We were one of the teams that went deep into this direction relatively early.

But before Mythos, this work was still mostly exploration by a small set of teams. The outside world's understanding often stayed at narrow questions: Can AI find a bug? Can an LLM write a PoC? Did the benchmark score improve?

Mythos significantly amplified attention and expected investment in this direction.

Once a frontier model company packaged automated vulnerability discovery as a complete industrial story, more companies started investing, more benchmarks appeared, more open-source projects got scanned, and more security teams began building their own auditing agents. Capability improvements then stopped coming from a single model alone. They started coming from an accelerating system: models, harnesses, orchestration, validation, patch generation, and disclosure workflows improving together.

So even without Mythos specifically, if Anthropic had used another sufficiently strong Claude version to run vulnerability discovery at scale and paired it with a similar narrative, this direction would probably have advanced along a similar path.

What made Mythos special is that it compressed the timeline.

It moved the industry from "this may happen" to "this is already happening, and we have to respond."

### The real acceleration is joint progress in models and systems

When people discuss AI vulnerability discovery, they often focus almost entirely on the model. That misses a large part of the engineering problem.

Models are obviously important. Better code understanding, vulnerability hypothesis generation, attack-path reasoning, semantic modeling, and PoC drafting all raise the ceiling. Mythos' progress on harder vulnerabilities, more complex exploit chains, and longer task horizons deserves attention.

But tool-call stability, environment construction, dynamic validation, evidence recording, state management, deduplication, and patch workflows are not simply "model capability." They are part of the whole system.

It helps to draw the boundary clearly:

- **Model**: vulnerability hypotheses, security semantics, entrypoint understanding, data-flow and state reasoning, attack-path construction, PoC drafts.
- **Harness**: build, run, isolation, instrumentation, observation, logging, crash collection, and trigger reproduction.
- **Orchestrator**: search strategy, state management, budget allocation, path prioritization, deduplication, and multi-round validation.
- **Validator**: disproving candidates, requiring reachability, attacker control, trust-boundary crossing, and impact evidence.
- **Governance**: moving confirmed issues into patching, disclosure, release, and downstream notification workflows.

Entry-point identification, data-flow tracking, state-machine understanding, and attack-path reasoning are mainly model and security-modeling capabilities. Building the project, running tests, instrumenting code, collecting traces, isolating risky behavior, and reproducing trigger paths belong more to the harness and toolchain. Multi-round search, deduplication, budget scheduling, retries, and evidence merging are orchestration. Validation, severity assignment, patching, regression, and disclosure are downstream governance.

Mixing all of these together makes the discussion blurry. Models raise the ceiling. Harnesses, orchestration, and validation determine whether that ceiling can be reliably realized on real repositories.

## Trend 1: Mid-Hanging Bugs Will Be Released Fast

<center><img src='/static/post-mythos-avd-trends/trend-01-inventory-release.png' /></center>

### High-value software will see a backlog-release window

In the next one to two years, I expect high-value infrastructure software to go through a temporary "backlog release" phase.

The backlog here is not the shallowest low-hanging fruit, nor the hardest problems that require entirely new vulnerability theory. It is the middle layer of issues that accumulated because human time, coverage, and validation cost were too high.

These issues include cross-module authorization mismatches, parser state-machine edges, configuration-permission combinations, protocol state transitions, and bugs that traditional fuzzing does not easily trigger but semantic search can locate. They do not necessarily require breakthrough research, but they require systematic code understanding, attack-surface enumeration, path exploration, and validation.

These bugs accumulated not because they were impossible to find, but because they were expensive to find. Human auditing requires experts to spend long periods inside a system. Traditional tools lack enough semantics. Validation and reproduction consume significant effort. AI agents push all of these costs down at the same time. Paths that once required a security researcher to spend days or weeks understanding can now be explored, filtered, and validated in batches.

Operating system kernels, browsers, cryptographic libraries, media parsers, databases, virtualization components, and server-side frameworks are all high-value targets. They have already seen years of manual review, fuzzing, and static analysis, but AI agents bring new search strategies and cheaper validation.

If a mature repository like Linux sees a temporary spike in reported vulnerabilities, that would not be surprising. It would not necessarily mean the project suddenly became worse. It may simply mean that years of accumulated risk are being released by a new class of tooling.

### This release will not continue forever

But the release window will not last forever.

Once high-value old repositories are scanned repeatedly by many AI systems, easier findings will become scarcer. Historical vulnerability inventory will be consumed, and newly introduced bugs will be caught earlier in development workflows.

This does not mean these projects will become perfectly secure. It means the marginal cost of finding new valuable bugs will rise again.

In the early phase, a mature system may discover many issues quickly through systematic scanning. Later, finding new high-value vulnerabilities will require stronger models, deeper domain knowledge, more complex environments, longer search, or better exploitability reasoning.

Automated vulnerability discovery will not eliminate the difficulty of security research. It will first consume problems that existed because systematic auditing was too expensive, and then push competition into harder regions.

### Competition will move toward the long tail and resource efficiency

After medium-difficulty bugs in top-tier projects start to decline, competition will shift in three directions.

First, who can scan more second-tier and long-tail repositories at lower cost. Real risk does not live only in famous infrastructure projects. It also lives in countless widely used projects with limited maintenance capacity.

Second, who can find higher-complexity vulnerabilities that depend on domain knowledge and cross-module understanding. These issues are not always discoverable through simple pattern matching or one-round review. Agents need to understand system semantics more deeply.

Third, who can embed vulnerability discovery into the development process so that bugs are absorbed internally before release.

This means vulnerability discovery will increasingly become a competition over resources and efficiency. The question is not who happened to find one bug. The question is who can find more real, important, fixable issues per unit of compute, time, and human review.

## Trend 2: The Focus Moves from "Finding a Bug" to "Sweeping the Repository"

<center><img src='/static/post-mythos-avd-trends/trend-02-repository-coverage.png' /></center>

### Finding one bug does not mean you audited a repository

From the outside, AI bug hunting can look magical: give a model a repository, let it read code, and it discovers a critical vulnerability.

But anyone who has done automated vulnerability discovery knows that finding one bug is not the hardest part. Given a large enough codebase, enough runtime, and enough attempts, finding some real vulnerabilities is not rare.

Many projects have never been systematically audited. Attack surfaces have been sitting there for years. The missing ingredient was not the existence of bugs, but a cheap, automated, continuous way to explore them.

Therefore, evaluating an AI vulnerability-discovery system by whether it found a bug is misleading. A system may accidentally hit a real issue without understanding the repository's security boundaries. It may do well in one module while missing a more important attack surface elsewhere.

The hard question is: can it sweep a repository relatively cleanly?

### Coverage comes from security modeling, orchestration, and observability

Strictly speaking, recall is hard to measure in real repositories because we rarely have complete ground truth. A more realistic standard is whether the system can establish strong coverage evidence: were major attack surfaces enumerated, key entrypoints exercised, important trust boundaries modeled, and candidate paths supported by evidence?

A usable vulnerability-discovery system cannot hit a few bugs in one module and call it a security audit. It must systematically understand repository structure, attack surface, trust boundaries, permission models, dangerous APIs, historical vulnerability patterns, and then use that information to decide exploration order.

Which directories matter? Which entrypoints should be exercised? Which data flows deserve tracking? Which permission boundaries are most error-prone? Which small modules have large impact if broken? These judgments mostly belong to model and security-modeling capability.

But after the judgment, orchestration and observability are needed to realize it.

Orchestration determines task decomposition, path priority, budget allocation, and which candidates need a second review. Harnesses and toolchains determine whether the project builds, tests run, coverage and logs can be observed, and fuzzing or static-analysis results can be pulled into the evidence chain.

Repository-level scanning needs reviewable receipts:

- Attack-surface inventory: entrypoints, trust boundaries, dangerous APIs, protocol states, files, network, IPC, and plugin extension points.
- Coverage receipts: which paths were inspected, which tools were run, which modules were actually executed, and which paths were only statically analyzed.
- Candidate ledger: candidate origin, deduplication result, validation failure reason, unvalidated paths, and remaining risk.
- Budget log: where time went, why these paths were prioritized, and which high-risk areas need another round.

This is why many systems can find vulnerabilities, but few can sweep a repository cleanly. Real coverage comes from models, security modeling, orchestration, tools, and runtime environments working together.

### High coverage and low noise pull against each other

High coverage and low noise are difficult to achieve together.

High coverage asks the system to explore more attack surfaces. Low noise asks the system to disturb maintainers less. These goals naturally conflict. Broader exploration creates more candidates. More candidates increase validation cost. Stricter validation reduces throughput.

The hard part of automated vulnerability discovery is not making a model say "this looks suspicious." It is getting the whole system to close the loop: discover a candidate, understand security semantics, form an attack hypothesis, validate exploitability, deduplicate, judge impact, generate a report, and assist remediation.

Even today, very few teams can simultaneously maintain high coverage and low noise.

This is my basic view of the current stage: for repositories that can be built, validated, and have reasonably clear attack surfaces, low-hanging and mid-difficulty vulnerabilities are not mysterious. What is scarce is the system capability to find them stably, in batches, and with low noise.

## Trend 3: System Capability Will Matter More Than One-Off Model Performance

<center><img src='/static/post-mythos-avd-trends/trend-03-system-stack.png' /></center>

### The model sets the ceiling; the system determines whether the ceiling is usable

Mythos made some higher-hanging bugs easier to reach, but it did not make the problem infinitely simple. Harder vulnerabilities still require stronger models, better harnesses, deeper domain knowledge, and longer search and validation.

Harnesses and orchestration are important, but that does not mean model capability is unimportant.

In fact, once low-hanging and medium-difficulty vulnerabilities are harvested, model capability becomes even more important. Higher-level vulnerabilities often require longer-range code understanding, more complex state reasoning, finer protocol and business semantic modeling, stronger exploit construction strategies, and more stable multi-round task execution. They are not guaranteed to appear just because you run the same system more times.

At the same time, real repositories do not become auditable automatically just because the model is stronger. They have build problems, dependency problems, environment differences, platform differences, missing tests, permission boundaries, runtime states, and lots of noise.

So the main battlefield after Mythos will not be a single model benchmark. It will be the overall efficiency of the model + harness + orchestrator + validator system.

### The same model can produce completely different results in different systems

The same model can behave very differently depending on the system around it.

One system may simply ask the model to read code and output candidate reports. Another system may build the target, run tests, instrument key paths, call static analysis and fuzzing tools, place candidates into a multi-round validation workflow, and adjust search strategy after failures.

The first is closer to "a model that writes security comments." The second is closer to "an automated auditing system that works."

System capability shows up in practical questions:

- Can the system reliably build and run the target project?
- Can it turn model hypotheses into executable validation tasks?
- Can it record failed paths instead of starting over every round?
- Can it merge duplicate candidates instead of reporting the same issue ten times?
- Can it disprove candidates instead of collecting only supportive evidence?
- Can confirmed issues flow into patching, testing, and disclosure?

These capabilities may not always appear in paper metrics, but they determine whether the system can operate on real repositories for a long time.

### Automated vulnerability discovery will become more engineering-heavy

Automated vulnerability discovery will increasingly look like an engineering system, not just a model demo.

It will have task queues, budget scheduling, coverage records, candidate ledgers, validation pipelines, regression tests, report templates, patch generation, maintainer collaboration interfaces, and disclosure state machines.

That sounds less dramatic than "the model found a 0day by itself." But it is the actual production form of this direction.

Mythos showed the industry the ceiling. The next gap is about who can turn that ceiling into stable, low-noise, high-coverage, governable output.

## Trend 4: False-Positive Governance Becomes a Core Moat

<center><img src='/static/post-mythos-avd-trends/trend-04-false-positive-funnel.png' /></center>

### A candidate is not a vulnerability report

AI is very good at producing candidates that look like vulnerabilities. It can point out that an input is not checked, a path may bypass authorization, a serialization routine looks dangerous, or a bounds check appears incomplete.

But there is a long distance between a candidate and a trustworthy report.

Is the path reachable? Can the attacker control the input? Does it cross a real trust boundary? Does it require unrealistic preconditions? Is it already filtered upstream? Is it a code smell rather than a security issue? Unless these questions are answered, maintainers will not trust the report.

If raw candidates go directly into maintainer inboxes, AI does not create defensive leverage. It creates governance debt.

### Evidence chains must prove reachability, control, and impact

A PoC is strong evidence, but not every vulnerability needs or can have a complete PoC. Many findings need a combination of reachability analysis, attacker-control proof, trust-boundary crossing, sanitizer traces, crash reproduction, minimal trigger tests, configuration assumptions, and code review.

A real system must build a validation evidence chain.

A good report should answer:

- What capability does the attacker have?
- Where does input enter, and can the attacker control it?
- What is the reachable path?
- Which trust boundary is crossed?
- Which sink or security property is affected?
- What is the reproduction artifact?
- How do the patch and regression test show risk reduction?

Without validation, system output is security noise. With an evidence chain, a candidate can become a vulnerability report that maintainers can process.

### Validation and remediation should be treated separately

Validation proves reachability, trigger conditions, and impact. Remediation generates a patch, regression tests, and review evidence to reduce recurrence.

If you merge these stages conceptually, the system may look end-to-end while every part remains weak.

A system that can write a patch has not necessarily proven the vulnerability exists. A system that can prove a vulnerability exists has not necessarily produced a mergeable, low-regression-risk patch. Validation systems, remediation systems, and disclosure systems should connect to each other, but they should not be treated as substitutes.

After Mythos, false-positive governance becomes a core moat. Systems that can be broad in coverage and hard in evidence are the ones maintainers, security teams, and enterprise development workflows can actually absorb.

## Trend 5: The Bottleneck Moves from Discovery to Governance

<center><img src='/static/post-mythos-avd-trends/trend-05-governance-bottleneck.png' /></center>

### After candidate discovery comes a much longer governance chain

In the past, the bottleneck in vulnerability discovery was mostly on the discovery side.

High-level security researchers were scarce. People who could audit complex codebases over long periods were even scarcer. Many open-source projects had not received systematic security review for years, so vulnerabilities naturally accumulated. Whoever could find them first had leverage.

As discovery capacity rises, the real questions become: who confirms the candidates, who patches them, who merges them, who releases the fix, who notifies downstream users, and who handles duplicates, low-quality reports, and disputed reports?

The chain needs to be split clearly:

1. Candidate discovery: the system proposes a possible security issue.
2. Intake, deduplication, and routing: merge duplicate reports, filter obvious noise, and assign priority.
3. Validation and severity: confirm reachability, impact, preconditions, and risk level.
4. Patch, test, and regression: generate a patch, run tests, review, and merge.
5. Disclosure, release, and downstream notification: coordinate CVEs, embargoes, advisories, version releases, and dependency notifications.

As discovery improves, the later steps become the new congestion points.

An unvalidated candidate is only a signal. An unpatched confirmed vulnerability is only risk inventory. A patch that is not merged and released still does not protect users.

### Confirmation, patching, and disclosure become the new battlefield

Future AI vulnerability-discovery systems should not be evaluated only by how many issues they report. We should ask how many are confirmed, patched, merged, released, and how much the time from discovery to remediation shrinks.

That is why [OpenAI's Patch the Planet](https://openai.com/index/patch-the-planet/), [Google DeepMind's CodeMender](https://deepmind.google/blog/introducing-codemender-an-ai-agent-for-code-security/), and Anthropic's Project Glasswing are worth watching. They do not stop at "finding vulnerabilities." They emphasize validation, remediation, collaboration, or controlled delivery.

The industry is realizing that improving discovery alone is not enough. Defensive value appears only after the vulnerability is absorbed.

Open-source ecosystems will feel the pressure first.

Many critical projects do not have dedicated security teams. Maintainers are already overloaded with issues, pull requests, releases, compatibility, and user support. If AI causes vulnerability reports to surge without corresponding validation, deduplication, and patch capability, maintainers receive burden rather than help.

Report quality will also diverge sharply. Some reports may be complete, with reproduction steps, impact analysis, patches, and tests. Others may be low-quality guesses generated from code snippets. Maintainers must distinguish between them, and that itself is labor.

If governance does not upgrade, stronger AI bug hunting can increase the noise in maintainer inboxes. High-quality vulnerabilities may get buried under low-quality reports.

### Disclosure workflows will become security tickets, not natural-language reports

Existing disclosure workflows were designed for a low-throughput era.

A researcher finds a vulnerability, writes a report, contacts the vendor, waits for confirmation, coordinates a CVE, and publishes a fix. This works when the number of reports is limited.

The AI era is different.

When a system can generate dozens or hundreds of candidates per day, traditional workflows can collapse. Worse, the stream contains real critical issues, low-quality AI slop, duplicate reports, half-validated claims, exaggerated impact, and reports without patches.

If we keep the old disclosure workflow, maintainers will spend too much time judging report quality and too little time fixing the issues that matter.

Future vulnerability reports will look more like security tickets than prose descriptions. They should include affected versions, entrypoints, attacker capabilities, reachable paths, crossed boundaries, impact, reproduction artifacts, suggested fixes, regression tests, and disclosure status.

Projects will also need new intake mechanisms. Not every report should go directly into a maintainer inbox. Reports should first go through automated routing, deduplication, validation, and prioritization. Reports missing reproduction steps, impact proof, or version information can be asked for more material. Duplicates can be merged. High-confidence, high-impact reports can be escalated.

This is counterintuitive: AI improves vulnerability discovery, but if governance does not improve, it may reduce the ecosystem's effective remediation capacity.

## Trend 6: Vulnerability Discovery Will Move into CI/CD and Release Workflows

<center><img src='/static/post-mythos-avd-trends/trend-06-cicd-shift-left.png' /></center>

### Security agents will enter mature teams' CI/CD first

In teams with higher security maturity, security agents will likely enter CI/CD workflows.

If AI agents can understand code changes, construct attack paths, generate validation ideas, and draft patches, they should not exist only as external scanners. They should become part of the development process.

Mature teams may run security agents before merge, before release, and before dependency upgrades. The agent does not just check formatting, run tests, or perform static scanning. It tries to understand whether a change introduces new attack surfaces, changes permission boundaries, or turns previously unreachable dangerous paths into reachable ones.

It also does not need to rescan the entire repository every time. A more realistic form is diff-scoped threat modeling: what entrypoints, permissions, dependencies, build steps, and release gates changed; which security boundaries were affected; which paths need deep scanning; and which candidates need sandbox reproduction.

Once this process matures, many vulnerabilities will be found and fixed before they enter public releases.

### Post-release external CVEs may decline in mature projects, but total CVEs may not

If vulnerability-discovery systems truly enter the software production line, the share of issues found externally after release may decline in high-maturity projects.

The reason is not that vulnerabilities disappear. More of them will be found, validated, and fixed internally before release. Issues that once required external researchers and public disclosure may be stopped at the pull-request stage.

This changes the vulnerability life cycle.

A bug moves from "found after release" to "found before merge," from "external disclosure drives remediation" to "internal quality workflow drives remediation," and from "CVE event" to "a failed security check in development."

But this does not mean total industry CVE volume will necessarily fall. In the short term, AI may improve both discovery and reporting, increasing public disclosure. In the long term, top-tier projects and long-tail projects may diverge: mature projects absorb more internally, while long-tail projects continue to expose unmanaged risk.

### Software growth will stretch the transition

This transition will not be quick.

Software volume is also exploding. AI makes code cheaper to write, which means more open-source projects, internal projects, generated code, one-off services, and AI-agent glue code. Many projects will not adopt high-quality scanning immediately, and many will not have resources to process the results.

We may therefore see two things at the same time: top-tier projects increasingly find and fix vulnerabilities internally, while long-tail projects continue to expose large amounts of unmanaged risk.

Automated vulnerability discovery will not make vulnerabilities disappear. It will change the order in which vulnerabilities are found, fixed, disclosed, and exploited.

Once vulnerability discovery moves into CI/CD, security competition shifts left. In the past, much of the competition happened after release: attackers, researchers, and defenders raced around software that was already public. In the future, more of that competition happens before release.

Whoever finds issues before merge reduces later disclosure and remediation cost. Whoever identifies supply-chain risk before dependency upgrades avoids new attack surfaces. Whoever verifies AI-generated code as it is produced reduces new AI-introduced risk.

Security becomes less of a post-release rescue action and more of a quality-control layer in the software production line.

## Trend 7: When Bugs Get Harder, Attackers Will Target Change Entry Points

<center><img src='/static/post-mythos-avd-trends/trend-07-change-entry-attacks.png' /></center>

### In some scenarios, poisoning is cheaper than harder 0day hunting

One more trend deserves attention: as vulnerabilities become harder to find, attackers may shift toward poisoning and supply-chain manipulation.

If top-tier projects are continuously scanned by AI agents and low-to-medium difficulty vulnerabilities gradually decline, the cost of pure 0day hunting rises again. For some targets and attacker models, another path may be cheaper: instead of finding an existing vulnerability, cause a future version to include an exploitable problem.

This is not a new attack idea, but AI changes the cost structure.

Attackers can use AI to find projects suitable for poisoning, generate pull requests more likely to be accepted, create more subtle code changes, craft more plausible justifications, and hide backdoor logic from traditional scanning.

As the natural vulnerability inventory is consumed, part of the offense-defense competition moves from "finding existing bugs" to "controlling change entry points."

### Supply-chain attacks are not all "creating bugs," but they bypass traditional bug-hunting cost

We should distinguish two kinds of issues.

One is planted vulnerabilities or backdoors. Attackers submit changes that look like normal fixes, refactors, performance improvements, or compatibility updates, but leave future exploitable paths in the project.

The other is supply-chain distribution compromise: malicious dependencies, typosquatting, maintainer account compromise, build-script poisoning, release-process hijacking, and dependency recommendation pollution. These are not always "creating bugs" inside code, but they bypass the cost of traditional 0day hunting by attacking how software reaches users.

Traditional vulnerability discovery focuses on bugs in code. Supply-chain attacks often focus on process, identity, trust, and distribution.

Future security systems therefore cannot look only at code. They must also look at how code enters the project, how it is built, how it is released, and how downstream users consume it.

### Security systems should detect abnormal signals, not claim to read intent

As AI coding tools spread, AI-generated pull requests and AI-recommended dependencies will introduce new risks.

Attackers may hide malicious logic inside changes that appear to be fixes, refactors, performance improvements, or compatibility updates. They may also poison documentation, issues, dependency ecosystems, and package names to influence AI tool suggestions so developers unintentionally import dangerous code or dependencies.

These problems are difficult because they do not always resemble traditional vulnerabilities with clear sources, dangerous operations, and exploit paths. They may look more like contextual inconsistency: code that appears functionally reasonable but introduces unnecessary permissions, abnormal network access, suspicious build behavior, or security-property changes outside test coverage.

Future security systems need to detect not only bugs, but also context-inconsistent behavior and capability growth.

They need to ask whether a change fits the project context, introduces unnecessary permissions, accesses unusual resources, modifies build or release paths, changes critical behavior outside test coverage, or comes from a trusted committer and distribution path.

This is harder than traditional vulnerability scanning.

Bugs can often be proven through program behavior. Malicious intent is much harder for a system to "read." A more robust approach is to infer risk from observable signals: abnormal permissions, abnormal dependencies, abnormal data flows, abnormal build steps, abnormal release paths, abnormal maintainer behavior, missing provenance, missing signatures, or missing build attestations.

After Mythos, both attackers and defenders will use AI. Defenders will use AI to find and fix vulnerabilities. Attackers will use AI to find more hidden and more economical entry points. Better vulnerability discovery will not end offense-defense competition. It will change its shape.

## Conclusion: The Main Battlefield Is Absorbing Discovery

Over the past few years, AI-driven automated vulnerability discovery has gone through several paradigm changes.

First, models were used as classifiers to decide whether a code snippet was vulnerable. Then LLMs helped fuzzing, static analysis, and rule generation. Then agentic auditing emerged: models could actively read code, call tools, form hypotheses, and validate them.

After Mythos, we are entering a new stage.

The central question is no longer "can AI find vulnerabilities?" The answer is clear: yes, and it will keep getting stronger.

The real question is whether systems can cover major attack surfaces, filter noise, complete validation and remediation, and be absorbed by maintainers.

Candidate discovery is only the first step. Systems also need to understand security semantics, prove exploitability, judge impact scope, generate high-quality reports, provide remediation plans, help maintainers merge patches, and connect all of this to real development workflows.

This requires teams to combine model capability, harness engineering, security research, productization, and ecosystem collaboration.

Simply knowing how to call models is not enough. Simply knowing how to run tools is not enough. Leading systems will connect model reasoning, tool execution, environment construction, dynamic validation, patch generation, and governance workflows.

In the post-Mythos era, the main battlefield of vulnerability discovery is no longer discovery alone. It is absorbing discovery.

The advantage will belong to those who can connect scanning output to the remediation chain: validation, patches, merge, release. If any link is missing, discovery capacity degrades into noise.

Mythos made the industry realize that the ceiling of automated vulnerability discovery is higher than many people expected. What determines the next stage is not only whether models keep getting stronger, but whether the whole vulnerability-governance system can keep up with the growth in discovery capacity.

If the Mythos Moment was a mobilization, the core task after Mythos is to turn the new discovery capacity it mobilized into real, sustainable, governable defense.

