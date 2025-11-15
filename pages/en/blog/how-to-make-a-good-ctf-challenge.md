---
title: How to Create a High-Quality CTF Challenge
date: 2019-06-02
abstract: Our team r3kapig provided 10 challenges (out of 13 total) for the recently concluded Baidu CTF, one of the DEFCON qualifier competitions, and served as the chief referee to control the competition format, some rules, and challenge quality. Baidu CTF is a new qualifier competition, and we also made some attempts, such as having AEG teams compete against top human teams in the same competition. Although some minor issues arose during the innovation process, we still contributed a qualified qualifier competition through everyone's joint efforts. Today, I want to use this competition as an opportunity to discuss my personal understanding of CTF challenges.
tags: [ctf]
---

Our team **r3kapig** provided 10 challenges (out of 13 total) for the recently concluded **Baidu CTF**, one of the DEFCON qualifier competitions, and served as the chief referee to control the competition format, some rules, and challenge quality. **Baidu CTF** is a new qualifier competition, and we also made some attempts, such as having AEG teams compete against top human teams in the same competition. Although some minor issues arose during the innovation process, we still contributed a qualified qualifier competition through everyone's joint efforts.

Today, I want to use this competition as an opportunity to discuss my personal understanding of CTF challenges.

## What Should a CTF Competition Test?

Before diving into the main topic, I want to ask an open-ended question:

> What should a CTF competition test?
> You might answer: **PWN / RE / Crypto / WEB**.

That's a great answer.

If I ask further:

> What should **PWN** test?

Your answer might be various exploitation techniques, such as:

- house of orange
- house of roman
- fastbin attack
- unsortedbin attack
- tcache attack
- ...and so on.

If you've participated in CTF competitions that are closer to real-world scenarios, your answer might also be exploitation techniques for major mainstream platforms, such as:

- Browser exploitation
- VM escape
- Kernel privilege escalation
- And so on.

Testing these essentially **bridges the gap between CTF and real-world scenarios**.

However, these are not my answers.
Moreover, I think the question itself is slightly biased.

So next, I want to start from these questions to introduce my current thoughts and perspectives on CTF.
These perspectives and thoughts are not necessarily correct, but I very much hope they can **spark discussion** and encourage everyone to think about these issues together.

## A CTF Competition Should Not Be an Exam

I believe **CTF should not be positioned as an exam**.

As everyone knows, the main purpose of exams is to assess participants' mastery and flexible application of knowledge.
Defining CTF as an exam means that most challenges focus on testing the mastery and flexible application of mainstream techniques.

However, security technology develops very rapidly.
For security research, **the ability to explore new challenges** is more important.

Unfortunately, most domestic competitions now position CTF as exams.
The content examined by most challenges is also the mastery of existing knowledge, such as the various exploitation techniques I mentioned earlier.

Some competitions even implement **full electromagnetic shielding** like exams, making it impossible to guide participants to explore new technologies (because there's no internet access).

Therefore, this question should be rephrased:

> What kind of challenges should a CTF competition have?

## What Kind of Challenges Should a CTF Competition Have?

Before answering this question, I first want to introduce what I consider to be **CTF challenge types**:

### 1. Idiotic Challenges
Test points that are meaningless brain teasers or too simple.
**Example**: Give a password-protected zip file with the hint "weak password" and have everyone guess it.
> These types of challenges are becoming increasingly rare, which is a good phenomenon.

### 2. Garbage Challenges
Test points that are difficult but boring.

**Example**: Reverse engineering of some obfuscated code.
If the challenge only tests whether participants can spend a huge amount of time reversing obfuscated code, then it's garbage.

The correct approach should be to share a new obfuscation or deobfuscation method through clever design.
However, in some competitions that consider themselves high-quality, these types of challenges still frequently appear as "high-quality difficult challenges."

### 3. Basic Challenges
Mainly test mastery and flexible application of mainstream techniques.
For example: testing various exploitation tricks in glibc heap.

Solvers who are proficient in these techniques can solve the challenge without Googling.

### 4. Intermediate Challenges
Can be considered an enhanced version of basic challenges, but still without innovation.
For example, increasing the difficulty of heap challenges by adding restrictions, but can still be bypassed using existing exploitation techniques.

> I believe that in most domestic competitions today, basic and intermediate challenges are still the mainstream.

### 5. Advanced Challenges
These types of challenges are more common in international competitions.
The test points are unfamiliar and interesting to most participants, and the challenge author guides participants to learn new ideas and knowledge through careful design.

**Example**:

- DEFCON 27 Quals' *Hotel California*
  - Tests the use of Intel TSX (Transactional Synchronization Extensions)
  - TSX is unfamiliar to most people, but the challenge guides participants to learn relevant knowledge
  - However, the final exploitation technique has a large gap from TSX, which can mislead thinking

### 6. Top-tier Challenges
Meet all conditions of advanced challenges and are more friendly to participants.

**Example**:

- HITCON CTF 2017's *babyfs*
  - Guides participants to learn the internal mechanisms of glibc File Objects
  - High difficulty, but the process allows continuous learning of new knowledge

> It's worth noting that:
> When a new exploitation technique is introduced for the first time, it's an advanced or top-tier challenge.
> But when it becomes widely known, using the same technique again becomes a basic or intermediate challenge.

## The Rise of High-Quality Real-World Challenges

Now **real-world challenges** are gradually becoming popular and are considered high-quality challenges.
I think an important reason is:

> Real-world attack and defense scenarios are both unfamiliar and interesting to most solvers.

But at the same time, this also means:
If in the future everyone masters exploitation techniques for mainstream platforms, then **creating another high-quality real-world challenge will become very difficult.**

## Final Summary

What kind of challenges should a CTF competition have? My view is as follows:

- **For novice participants (such as school competitions)**
  → Primarily basic and intermediate challenges to guide them in learning new knowledge.

- **For competitions balancing veteran teams and newcomers**
  → Balance the ratio of basic/intermediate and advanced challenges, considering both difficulty and cost.

- **For international top teams (such as DEFCON qualifiers)**
  → Primarily advanced and top-tier challenges.

> Idiotic challenges and garbage challenges should appear as infrequently as possible in any competition.
