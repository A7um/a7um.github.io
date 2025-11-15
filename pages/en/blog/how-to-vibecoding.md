---
title: "How to Make VibeCoding Truly Useful"
date: 2025-10-09
abstract: >
  Recently, VibeCoding has become a new trend in the development community. With tools like Cursor and Claude Code, developers only need to describe requirements and AI can automatically generate code. From batch completing repetitive code to quickly building prototypes and refactoring legacy code, it greatly improves development efficiency. In our attempts, we found it can fully handle medium-difficulty engineering development work. The productivity boost it brings is impressive. However, many people feel disappointed when first encountering it: AI-written code doesn't run, changes mess up the project, and they end up returning to manual coding or asking questions in regular AI chat interfaces while writing.
tags: [software-engineering]
---

**Author: Guancheng Li and Jiashuo Liang of Tencent Xuanwu Lab**

Recently, VibeCoding has become a new trend in the development community. With tools like Cursor and Claude Code, developers only need to describe requirements and AI can automatically generate code. From batch completing repetitive code to quickly building prototypes and refactoring legacy code, it greatly improves development efficiency. In our attempts, we found it can fully handle medium-difficulty engineering development work. The productivity boost it brings is impressive. However, many people feel disappointed when first encountering it: AI-written code doesn't run, changes mess up the project, and they end up returning to "manual coding" or asking questions in regular AI chat interfaces while writing. This creates a gap—enthusiasts sharing their efficiency experiences on one side, and frustrated new users on the other.

Why is this? The reason is that VibeCoding Agent is essentially just a tool. It has powerful potential, but users need to master certain usage methods. Although platforms provide many "best practices" checklists, most are scattered and trivial, difficult to apply directly, making it hard to form a systematic understanding.

This article will try to return to fundamentals, starting from a few core principles, explaining how to make VibeCoding truly useful as a new productivity tool.

## Principle 1: Clear Communication

Many people are accustomed to giving AI instructions based on intuition during VibeCoding, but overlook a key fact: the project background knowledge in your brain is unknown to AI. Most failed cases are not because the model isn't strong enough, but because requirements weren't clearly communicated.

### Imagine the Agent as a New Teammate Joining the Team

You can imagine a new colleague joining the project team. When facing a newcomer, syncing the current project progress is a problem that needs to be handled well. You might start by introducing the overall structure of the project, then gradually explain the specific tasks they'll be responsible for.

The same principle applies to AI, except AI is more efficient and communication is simpler:
* AI reads code and organizes language responses very quickly—you can ask it to read various code and restate its understanding of the problem;
* If AI's understanding is wrong, you can immediately interrupt and continue discussing with it.

Most VibeCoding tools provide a "Plan Mode," which is a very useful mechanism. In this mode, the Agent doesn't immediately execute instructions but only outputs an execution plan. You can align goals with the Agent until you're certain it fully understands your task, then allow it to write code.

### Let the Agent Gradually Deepen Its Understanding of the Project

Prepare concise project documentation and task description documents in the project, having AI read these contents before each execution. This way, it will more easily place the current task within the context of the entire system.

After each task is successfully completed, you can also have the Agent generate a summary document recording its understanding of the project structure, implementation logic, and reasons for changes. Save these records in project files or rule files like CLAUDE.md as long-term memory. This way, during the next VibeCoding session, issues that have been discussed won't need to be discussed again.

## Principle 2: Understand VibeCoding's Strengths and Weaknesses

Many people treat AI as an omnipotent expert during VibeCoding, thinking it can modify the entire system at once. But the fact is, AI is very reliable in some scenarios and prone to errors in others. If you don't understand its advantages and limitations, you'll have overly high expectations, and the result is often disappointment.

### AI's Weaknesses

Longer context leads to worse performance: When tasks involve multiple files and overly long context, large language model performance significantly degrades;

Starts working before fully understanding: Even without thorough understanding, it will confidently start working, which makes it easy to go off track;

Loves shortcuts: It sometimes tends to choose the simplest implementation. For example, when refactoring a dict to a pydantic model, it might lazily write a converter instead of thoroughly replacing it at the code level.

### AI's Strengths

Fast, still fast: This advantage was mentioned earlier, but because it's so important, I'll emphasize it again. VibeCoding's ability to read and write text and code far exceeds humans, so you can confidently communicate with it frequently to align requirements, have it read various files to deepen project understanding, and have it write down its understanding for future reuse. You can imagine it as a colleague with quantum speed reading and writing abilities, then think about how to properly utilize this capability.

Familiar with and masters a large number of engineering best practices: It knows how common project directory structures should be organized; it understands common design patterns, unit testing methods, type annotation habits; when it sees a piece of code, it can immediately associate it with better practices from mainstream engineering standards. This means that during VibeCoding, you don't just need to have it mechanically complete changes—you can also have it proactively suggest improvements. Each VibeCoding session is not just completing a task, but an opportunity to gradually evolve the codebase.

### How to Leverage Strengths and Avoid Weaknesses

To make VibeCoding Agent perform well, first control context length. For example, first use Plan Mode to have the Agent break down complex tasks into smaller subtasks, then start new conversations to complete these tasks. If code modularization and abstraction design are reasonable, the Agent can understand the functions and relationships of different modules from an abstract perspective. Even complex cross-module development tasks can maintain good performance, which will be explained in detail in Principle 3.

Second, to prevent it from starting work before fully understanding, we can use the Plan Mode technique mentioned in Principle 1: first have it explain its understanding, confirm whether the goal is accurate, and only let it execute after it "understands."

For its tendency to take shortcuts, we can add clear constraints in task instructions: require it to provide multiple implementation approaches before execution and compare their pros and cons; specifically emphasize not to use lazy solutions like "just wrapping a converter"; when generating plans, exclude paths that obviously take shortcuts, ensuring it takes routes that truly align with long-term goals.

Finally, there's an easily overlooked point: VibeCoding Agent's summarizing and retrospective abilities are also very strong. After each task completion, you can ask it to write down "why it did this" and "what alternative solutions exist." This both helps you check for errors and omissions and helps AI inherit experience in subsequent sessions, making collaboration smoother over time.

## Principle 3: Design AI-Friendly Code Structure

To have VibeCoding stably produce high-quality code, in addition to the principles mentioned above, you can also design AI-friendly code structures. By improving project organization methods, humans and AI can efficiently collaborate to jointly maintain a clear and maintainable system.

An AI-friendly code structure not only allows the model to locate related code faster but also enhances project maintainability, making subsequent VibeCoding processes smoother.

### Code Structure Problems and Causes from AI Output

VibeCoding tools have powerful programming capabilities, but their output code structure tends to have the following problems:
* Lack of reasonable abstraction — high coupling between modules, cross-functionality, unclear module boundaries.
* Over-encapsulation, redundant code — many unnecessary intermediate layers and compatibility layers.
* Inconsistent naming, chaotic style, duplicate functionality with other modules.

These problems gradually accumulate, not only reducing human developers' reading and maintenance efficiency but also hindering Agent performance in subsequent tasks.

Through long-term observation and practice, we've summarized the causes of these problems:
* Agents tend to make small patches on existing code to support new functionality. Unless users require it, Agents won't proactively take destructive actions like deleting old code or major refactoring. The more patches applied, the messier the code becomes.
* Agents prioritize completing user-specified tasks as their primary goal. After achieving the goal, the conversation ends. But the current task may have indirectly affected other functionality, and AI won't holistically evaluate the reasonableness of the task completion method afterward.
* Failed to retrieve some key code, causing the Agent to not understand existing module functionality and style, so it reinvents the wheel.
* Agent's project background cognition is inconsistent with humans. It references common approaches in training data, mistakenly thinking some unimportant features need abstraction while not abstracting modules that should be abstracted.

### Co-building Good Code Structure with AI

"AI-friendly" doesn't mean sacrificing human readability. The two are actually highly overlapping: if the code structure is clear to humans with well-defined responsibility boundaries, AI will also find it easier to contribute. Traditional software engineering principles like high cohesion and low coupling still apply. The difference is that under VibeCoding mode, AI also becomes a participant in code structure governance. We can adjust organization methods based on its characteristics to make projects more maintainable.

* Document-oriented programming. Pre-write two types of documents in the project: project introduction documentation (usually includes overall project background, abstraction layers and module relationships), coding standard documentation (usually includes code style guidelines, third-party dependency relationships). Have AI automatically add required documents to context for each task.

* Involve AI in architecture design. During the architecture design phase, you can discuss with AI what kind of functional module design and code abstraction levels should be used to achieve project goals. Revise repeatedly until you think it's reliable. Write the final discussion results into project documentation as ground truth for subsequent programming.

* Avoid overly complex single files. VibeCoding tools read code on a file-by-file basis; overly large files can easily cause AI to "lose focus." In code structure, try to divide code modules into independent units as much as possible. Each module should focus on one thing, have clear responsibilities, expose a clear set of interfaces, and not require dependencies across many files to understand the module's functionality.

* Automated testing. Have AI generate related unit tests after current functionality implementation is complete. This not only helps AI automatically discover and fix some bugs but also prevents AI from indirectly affecting this module's functionality in subsequent tasks without awareness.

* Code review and refactoring. When projects gradually become complex, when the original code structure cannot handle new functional requirements in the foreseeable future, you can discuss and plan code refactoring solutions with AI, perform appropriate abstraction to enhance scalability, decouple complex functions, merge similar functions, and update documentation.

Reference
* https://www.anthropic.com/engineering/claude-code-best-practices
* https://waytoagi.feishu.cn/wiki/AtHvwye9Ki3vBykkIl0cEpMYnsf
