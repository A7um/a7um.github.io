---
title: "After Claude Mythos: What Keeps Security Practitioners From Becoming Obsolete?"
date: 2026-04-08
tags: [software-security, AI, career]
abstract: >
  Anthropic launched Project Glasswing and Claude Mythos Preview, demonstrating formidable automated vulnerability capabilities across OpenBSD, FFmpeg, the Linux kernel, and more. This post asks where security practitioners should anchor their value as execution-layer skills become increasingly automatable—from “doing the work” to “deciding what work matters,” why higher-level judgment resists replacement longer, and how mastering AI agents becomes the new universal baseline.
---

Last month, Anthropic announced Project Glasswing, alongside AWS, Apple, Google, Microsoft, NVIDIA, CrowdStrike, Palo Alto Networks, and others—twelve companies in total—with the goal of using AI to protect the software security of critical infrastructure worldwide.

The immediate catalyst was a model Anthropic trained internally: Claude Mythos Preview. It found a 27‑year‑old remote vulnerability in OpenBSD, uncovered a 16‑year‑old bug in FFmpeg that automation had “hit” five million times without ever triggering, and chained multiple kernel issues into a full privilege‑escalation exploit on Linux. It scored 83.1% on CyberGym vulnerability reproduction and 93.9% on SWE‑bench Verified.

Those numbers speak for themselves; I will not waste breath marveling at them. What I want to talk about instead is how security practitioners should think about all of this.

<!--more-->

## Execution-layer skills are on track to be absorbed

Vulnerability research, reverse engineering, penetration testing, alert triage, incident attribution—the industry often calls these “foundational skills” or “core craft.” Many people’s professional identity rests on them.

But these tasks share a property: success has an unambiguous verdict. Either you crash the program and get code execution, or you do not. Either you get a shell and escalate privileges, or you do not. Alert triage ends in a clear true or false. That “you can tell at a glance whether it worked” quality is exactly what AI is best at attacking. Mythos is not the end state—it is the beginning. The next generation will be stronger; that is not in doubt.

So we do not need another round of “can AI replace these skills?” It can, and it will do so more thoroughly over time. The question worth debating is: if those skills are absorbed, where does a security practitioner’s value anchor move to?

## From “doing the work” to “deciding what work matters”

Once the execution layer is automated, there is only one direction left: think from a higher vantage point.

Take a concrete example. Suppose you are a reverse engineer who spends your days tearing apart binaries and analyzing samples. AI is taking over those tasks. You do not necessarily need to change careers—you need to start operating with your manager’s lens.

Your manager may rarely reverse binaries themselves. They worry about: Where is the team headed? Which samples deserve priority? How do we allocate work? How do we judge quality? Now imagine you have five AI agents and several times the throughput you used to have. You are effectively a lead with five agents—you must decide what is worth doing, in what order, and how to verify that agent output is actually useful. Everything you think about needs to move up a level.

When you stand in that seat, you see what managers have always seen: a backlog of things they know they should do but had to defer because resources did not stretch. For example, your red team may constantly need evasion, and the right answer is to reverse the AV’s detection logic—not to black‑box endless samples. In the past, all reverse bandwidth went elsewhere, so that work stayed on the shelf. With agents multiplying execution, those tradeoffs reopen—you can task an agent to reverse the detection engine and help your red team fix evasion at the root.

The same logic applies at every level. A team lead thinks like a director about cross‑team coordination and budget; a director thinks like a CISO about company‑wide strategy. Each step up adds context to reconcile, stakeholders to balance, and tradeoffs to make.


Moreover — once AI raises execution efficiency across the board, every backlogged initiative that leaders "knew we should do but never had the resources for" suddenly becomes actionable. Someone has to step in and own those. On the flip side, when attackers gain the same capabilities, enterprises are no longer facing scattered human hackers — they're up against AI-army-grade firepower. Zero-days are no longer scarce, penetration can run 7×24 without pause, and the assumptions behind traditional defense architectures get torn apart. New frameworks, new strategies, new judgment calls — all of it needs people. From both angles, there's more work, not less. Organizations won't discard those who successfully level up; the demand for them will only grow. The ones who get left behind are those who refuse to evolve — clinging to "all I know is manually triaging samples" as the world moves on.

## The baseline skill at every level

Whatever your level, one thing is universal: you must learn to wield AI agents.

Everything above—thinking like your boss, surfacing new directions—depends on one premise: you can direct agents to execute effectively. Otherwise, high‑level thinking never lands.

An AI agent is not “just a tool.” It is closer to an employee—one you can duplicate infinitely, scale on demand, and run around the clock. But “more employees” does not mean “better outcomes.” Anyone who has led teams knows a room full of smart individuals is not automatically a high‑performing team. You tune collaboration to people’s strengths. Agents are no different.

You need to learn: how to decompose tasks so agents complete them reliably; which weak spots need Skills or tooling; how to design execution flows and runtime environments; how to run multiple agents in parallel without stepping on each other. There is no one‑size‑fits‑all answer—it depends on your work, your environment, and your sense of each agent’s limits. You are essentially calibrating collaboration with a new kind of coworker.

A reverse engineer who truly knows how to wield agents may output what an entire team used to produce, with more breadth and depth—that is leverage. Whoever pulls that lever first becomes the new “super‑individual.”

## Why higher-level judgment is harder to replace

Someone may ask: if AI keeps improving, will not this “move up a level” mindset eventually be obsolete too?

Perhaps—but the higher you go, the slower that process is likely to be. That comes down to a basic fact about how AI learns.

AI can chew through vulnerability research and pentesting quickly because the reward signal is crisp—success or failure is obvious, feedback loops are short, and models can iterate at scale. That is where reinforcement learning shines.

As you move up the security org chart, those conditions erode.

A director’s day might look like this: twenty vulnerabilities to fix, product pushing to ship, a compliance audit next month, and a fixed budget—which comes first? Every choice balances competing interests: security wants everything patched, product wants speed, finance wants cost control, legal worries about regulatory exposure. The context they integrate is an order of magnitude larger than an engineer’s, and whether a decision was “right” may take months to tell. Feedback is no longer measured in minutes; it is measured in quarters.

At the CISO level, abstraction jumps again. Board members, regulators, business units, and engineering teams all pull in different directions; decisions are made on incomplete information and reverberate for years—should this year’s spend emphasize supply chain risk or AI risk? After an incident, when and how do you disclose, and whom do you brief first? Do you grow the security team or shrink headcount with AI and move budget elsewhere? Feedback cycles can run one to two years or longer, and even in hindsight it is hard to attribute outcomes to a single decision—execution may have failed, the threat landscape may have shifted, or luck may have played a role.

The pattern is clear: the higher you go, the more context you must synthesize, the more judgment becomes about balancing conflicting goals rather than optimizing under crisp criteria.

From a training perspective, that means effective supervision signals get scarcer as you go up. Year‑scale feedback loops break classic RL iteration; causality is muddy; worst of all, there is often no “correct answer,” only “a reasonable choice given the constraints and politics of that moment”—you cannot label a dataset where one decision is +1 and another is −1.

Today, frontier labs mostly train on tasks with clear rewards (like coding) and hope general reasoning transfers to tasks with no clean reward signal (like high‑stakes judgment). If that path truly works, AGI may be closer than we think. Until then, it is reasonable to say: AI may find a 27‑year‑old bug in hours, but it cannot tell you—given your company’s stage, compliance pressure, team morale, and budget—what the next critical investment should be. That kind of judgment is less about raw technical strength than about people, organizations, and power structures.

## Closing thought

One detail in Project Glasswing is worth sitting with: Anthropic may currently operate one of the strongest automated vulnerability engines on the planet, and it could have kept it in‑house. Instead, it brought in twelve companies and more than forty organizations, committed $100 million in usage credits, and donated $4 million to open source.

Because finding the bug has never been the hardest part. Remediation, coordination, disclosure, compliance, and driving fixes to completion require human coordination, trust between organizations, and standards bodies. None of that is something AI can do today.

The stronger AI becomes, the more human value sits in judgment, coordination, and governance—but that value accrues only to people willing to lift their gaze and see the whole board.
