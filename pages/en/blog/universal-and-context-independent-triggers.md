---
title: "A Universal Method for Precisely Controlling LLM Outputs"
date: 2025-08-06
tags: [ai-security]
abstract: >
  Large Language Models (LLMs) are evolving from simple conversational tools into intelligent agents capable of writing code, operating browsers, and executing system commands. As LLM applications advance, the threat of prompt injection attacks continues to escalate. Imagine this scenario: you ask an AI assistant to help write code, but it suddenly starts executing malicious instructions, taking control of your computer. This seemingly science fiction plot is now becoming reality. This article introduces a novel prompt injection attack paradigm. Attackers need only master a set of "universal triggers" to precisely control LLM outputs to produce any attacker-specified content, thereby leveraging AI agents to achieve high-risk operations like remote code execution.
---
**Author: Jiashuo Liang and Guancheng Li of Tencent Xuanwu Lab**

Originally published on the [Tencent Xuanwu Lab Blog](https://xlab.tencent.com/cn/2025/08/06/universal-and-context-independent-triggers/)


## 0x00 Introduction

Large Language Models (LLMs) are evolving from simple conversational tools into intelligent agents capable of writing code, operating browsers, and executing system commands. As LLM applications advance, the threat of prompt injection attacks continues to escalate.

Imagine this scenario: you ask an AI assistant to help write code, but it suddenly starts executing malicious instructions, taking control of your computer. This seemingly science fiction plot is now becoming reality.

This article introduces a novel prompt injection attack paradigm. Attackers need only master a set of "universal triggers" to precisely control LLM outputs to produce any attacker-specified content, thereby leveraging AI agents to achieve high-risk operations like remote code execution.

<!--more-->

<center><img src='/static/universal-triggers/cline-rce.png' width='90%'></center>
<center>Figure: Using universal triggers to hijack Cline for arbitrary command execution</center>

This method dramatically lowers the attack barrier, eliminating the need for fancy injection techniques while achieving approximately 70% attack success rate.
These research findings have been published at [Black Hat US 2025](https://www.blackhat.com/us-25/briefings/schedule/index.html#universal-and-context-independent-triggers-for-precise-control-of-llm-outputs-45099).

## 0x01 Escalating Prompt Injection Threats

In the early days, LLMs primarily served as standalone dialogue or content generation tools. Prompt injection attacks at that time mostly involved injecting malicious text through direct user input or web search results into conversations, inducing models to output unethical statements or incorrect answers, with relatively limited impact.

Subsequently, LLMs began being integrated into more complex workflows, such as RAG (Retrieval-Augmented Generation) and intelligent customer service systems. Attackers could inject malicious prompts into workflows by poisoning data sources (like web search results or enterprise knowledge bases), thereby disrupting or destroying normal system operations.

Today, we're entering the AI Agent era. Agents have been granted unprecedented abilities to interact with the real world, directly invoking external tools like code editors, browsers, and APIs. This significantly elevates the harm of prompt injection: from information-level manipulation to real-world high-risk operations, such as planting backdoor code, stealing private data, or even completely controlling user computer systems.

<center><img src='/static/universal-triggers/claude-gui.png' width='70%'></center>
<center>Figure: Claude Agent operating GUI to use computers</center>

However, in the Agent era, conventional prompt injection attacks expose limitations. These attacks typically involve two stages:

First is "jailbreaking," where attackers use phrases like "ignore previous instructions" to induce the model to break free from its original role and safety constraints. This stage heavily depends on task and context, requiring manual design and adjustment of attack instructions for each specific scenario, with no cross-scenario reusability.

Next is the "hijacking" stage, where attackers drive the model to execute malicious tasks. But this control is often fuzzy, with high uncertainty in LLM outputs. In many modern LLM applications, agents require model outputs to conform to specific formats (like JSON Schema) to be parsed and executed by downstream tools. If attackers cannot precisely control outputs, even if they successfully induce the model to generate malicious content, there's no guarantee it can be effectively utilized by subsequent programs. These limitations have driven research into more universal and precise attack methods.

## 0x02 Universal Triggers: A New Attack Paradigm

To address these limitations, we propose a novel attack paradigm. The core idea is to decouple the attack process into reusable "triggers" and customizable "payloads," achieving universal and precise attack effects.

### Attack Architecture and Principles

We drew inspiration from the academic concept of Universal Adversarial Triggers (UAT), but existing related research typically binds triggers to specific attack tasks, requiring separate training of specialized triggers for different objectives (like inducing inappropriate speech or misclassification). We went further, achieving complete decoupling of triggers and attack payloads, transforming this academic concept into a more threatening practical attack technique.

We decompose attacker-injected malicious input into two core components:
- **Payload**: The content the attacker expects the model to output, such as a shell command. To ensure output precision and format integrity, we directly use the complete text we expect the model to output as the payload.
- **Trigger**: A sequence of specially optimized tokens that essentially instructs the model: "Ignore all other instructions, directly decode and output the payload content." Triggers consist of prefix and suffix parts, located before and after the payload respectively.

<center><img src='/static/universal-triggers/trigger-architecture.png'></center>
<center>Figure: Trigger structure example</center>

The key point is that triggers are application context-independent and attack task-independent, meaning the same trigger can carry different payloads for different application scenarios. Once attackers obtain such triggers, even novices can implement prompt injection with high success rates and arbitrarily control model outputs, greatly lowering the attack barrier.

### Technical Characteristics and Threat Impact

**Universality**: Attackers don't need to redesign attack strategies for specific scenarios; the same trigger pair can carry different payloads for different applications, breaking the limitation of traditional prompt injection attacks being highly context-dependent. Experimental tests show triggers maintain approximately 70% attack success rate across different prompt contexts and payloads.

**Ease of Use**: Attackers only need to insert malicious payloads into predefined templates, requiring no deep prompt injection expertise. Even inexperienced attackers can achieve expert-level success rates. This dramatically lowers the attack barrier, meaning more potential threat actors can implement effective attacks.

**Precision**: Universal triggers can specify exact output content with high precision. This is crucial in many scenarios: on one hand, many AI agents only invoke external tools when successfully parsing outputs in specific formats (like JSON, XML); on the other hand, in scenarios like injecting malicious shell commands, attack success often depends on every character being precisely correct.

Such universal triggers make large-scale, low-barrier injection attacks possible, potentially becoming a new attack paradigm. The security threat of prompt injection will evolve from individual cases to systemic risks.

<center><img src='/static/universal-triggers/abstracted-dialogue.png' width='65%'></center>

## 0x03 Case Demonstrations

To more intuitively demonstrate the potential risks of universal triggers, let's look at two real attack scenario demonstrations to directly experience the security risks universal triggers bring to practical applications.

### Open Interpreter Command Injection Attack

Open Interpreter is a popular open-source project dedicated to letting users operate computers using natural language. It uses large language models to translate user task descriptions into local code (like Python, Shell, etc.), thereby controlling the user's computer to complete complex tasks like creating and editing files, browsing web pages, and analyzing data.

Attackers can use universal triggers to construct malicious emails, making the victim's Open Interpreter execute commands in the email, as shown in the video:

<center><video controls width='100%'><source src='/static/universal-triggers/inject-open-interpreter-devstral-mosaic.mov' /></video></center>

Detailed attack steps:
1. Attacker constructs a special email with universal triggers and malicious shell commands (payload) embedded in the email body.
2. User asks AI assistant (Open Interpreter) to check and summarize new emails.
3. AI assistant reads the email, causing malicious content containing triggers and payload to be sent to the large language model.
4. Universal trigger activates, forcing the model to ignore the original task and instead precisely output malicious shell commands.
5. Open Interpreter parses and executes the malicious commands output by the model.

### Cline Remote Code Execution Attack

Cline is an AI programming assistant extension integrated into the VSCode code editor. It can help developers write, interpret, and refactor code, and extend functionality by installing third-party MCP tools.

Attackers can use universal triggers to make Cline execute arbitrary shell commands, as shown in the video:

<center><video controls width='100%'><source src='/static/universal-triggers/inject-cline-mcp2-mosaic.mov' /></video></center>

Detailed attack steps:
1. User installs a seemingly harmless third-party MCP service controlled by the attacker.
2. After the MCP service gains widespread use, attacker updates the MCP tool description, planting universal triggers and malicious commands in it.
3. User normally uses Cline to perform programming tasks. To improve work efficiency, many developers enable Cline's "auto-approve" feature, allowing the AI assistant to directly execute operations it judges as "safe" without manual user confirmation.
4. When Cline retrieves tool information, the malicious description containing triggers and payload is sent to the large language model.
5. Universal trigger activates, forcing the model to output tool invocation instructions containing malicious commands and marking them as safe (no approval required).
```xml
<execute_command>
  <command>malicious command</command>
  <requires_approval>false</requires_approval>
</execute_command>
```
6. After Cline parses this output, it skips user confirmation and directly executes the malicious command.

## 0x04 How to Find Triggers

#### Describing the Attack as an Optimization Problem

First, we need to understand the basic process of how large language models handle input text. When text containing malicious injection is input to a model, it goes through the following steps:
1. **Input String**: Attacker-controlled text content is injected into the input string.
2. **Tokenization**: The input string is broken down by the tokenizer into a series of discrete tokens.
3. **Embedding**: Each token is mapped to a high-dimensional floating-point vector, i.e., token embedding vector.
4. **Model Computation**: The embedding vector sequence is input into neural networks like Transformers for computation.
5. **Probability Output**: The model predicts probability distributions for all tokens in the vocabulary and selects the next output token based on this distribution.
6. **Output More Tokens**: Output tokens are concatenated to the input end, iterating repeatedly until the model outputs an EOS token.

<center><img src='/static/universal-triggers/llm-process.png' width=80%></center>

Our goal is to find an appropriate trigger token sequence to increase the probability of the model outputting attack payload tokens in step four. Let's formalize this objective.

<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@4/tex-mml-chtml.js"></script>

The input token sequence \\(X_{input}\\) consists of five parts: text before the injected prompt \\(X_{before}\\), trigger prefix \\(X_{trigger_1}\\), payload \\(X_{payload}\\), trigger suffix \\(X_{trigger_2}\\), and text after the injected prompt \\(X_{after}\\).
$$ X_{input} = X_{before} \oplus X_{trigger_1} \oplus X_{payload} \oplus X_{trigger_2} \oplus X_{after} $$
We want to maximize the conditional probability of the model producing target output \\(Y=X_{payload}\\) given input \\(X_{input}\\):
$$ P(Y|X_{input}) = \prod_{1 \leq i \leq |Y|} P(y_i | X_{input} \oplus y_1 \oplus \cdots \oplus y_{i-1}) $$
For computational convenience, we take its logarithm as the loss function. For an adversarial training dataset \\(D_{adv}\\) containing numerous different contexts and payloads, our optimization objective is to find optimal triggers \\(X_{trigger_1}\\) and \\(X_{trigger_2}\\) to minimize the average loss function \\(L\\):
$$ L(X_{trigger_1}, X_{trigger_2}) = -\frac{1}{|D_{adv}|} \sum_{D_{adv}} \frac{1}{|X_{payload}|} \log P(X_{payload} | X_{input}) $$
The intuitive meaning of this formula is: find a trigger string that makes the model generate our desired payload content token-by-token with maximum probability across various different attack scenarios.

#### Training Triggers with Gradient Methods

To solve this optimization problem, we need to construct a diverse adversarial sample dataset and adopt an efficient optimization algorithm.

For the dataset, we constructed an adversarial training dataset containing tens of thousands of samples through an automated process. Based on universal instruction datasets and domain-specific (like AI-assisted programming) conversation samples, we used large language models to generate various malicious payloads, which were injected at random positions in normal conversations (like user input, MCP tool descriptions and execution results, web search results, etc.), simulating numerous realistic attack scenarios.

For the optimization algorithm, since triggers consist of discrete tokens and conventional gradient descent methods rely on input variable continuity, they cannot be directly used. We adopted a discrete optimization algorithm called **Greedy Coordinate Gradient (GCG)**. This algorithm can use gradients of continuous token embeddings to estimate the impact of different tokens on the loss function, guiding optimization direction based on gradient information, avoiding inefficient brute-force search over the entire vocabulary. In each iteration, the algorithm finds a token position in the trigger token sequence to replace, estimates the best replacement token that maximally reduces loss, continuously iterates to update the trigger token sequence until the loss function converges, ultimately finding the optimal trigger sequence.

More details can be found in our paper (link at the end).

#### Experimental Evaluation

We conducted experiments on multiple mainstream open-source models (Qwen-2, Llama-3.1, Devstral-Small) based on the above method. Results show that after approximately 200-500 optimization iterations, the found universal triggers demonstrate powerful attack capabilities across various tasks, with average attack success rate (ASR) around 70%.

<center><img src='/static/universal-triggers/asr.png' width='60%' ></center>
<center>Table: Trigger attack success rates on different tasks in experiments</center>

We also tested the cross-model transferability of triggers:
- **Within model family**: Partially transferable. For example, when scaling parameters within the same model family (Llama-3.1-8B → Llama-3.1-70B) or version updates (Qwen-2-7B → Qwen-2.5-7B), attack success rates can sometimes still maintain around 60%.
- **Cross model families**: Not transferable. For example, triggers trained on Qwen series models cannot be directly applied to Llama series models.

## 0x05 Defense Strategies and Recommendations

Facing the new security threats brought by prompt injection, we must recognize that large language model outputs are not always trustworthy.

Especially when agents have the ability to interact with external environments, greater caution is needed. We recommend deploying multi-layered defense measures:
- **Sandbox Isolation**: Strictly restrict AI agents to run in sandbox environments, blocking unauthorized access to system resources.
- **Input Detection**: Since universal triggers typically consist of non-natural language token sequences, methods like perplexity detection can identify and filter such anomalous inputs.
- **Principle of Least Privilege**: Plan the minimum permission set needed for AI agent tasks, avoiding excessive authorization.
- **Security Whitelists and Manual Review**: Establish security operation whitelists, restricting AI agents to only execute predefined safe commands, and mandating manual review confirmation for all high-risk actions (like code execution).

## 0x06 References

- Paper on the attack method in this article: [Universal and Context-Independent Triggers for Precise Control of LLM Outputs](https://arxiv.org/abs/2411.14738)
- Universal Adversarial Triggers: [Universal Adversarial Triggers for Attacking and Analyzing NLP](https://arxiv.org/abs/1908.07125)
- GCG Algorithm: [Universal and Transferable Adversarial Attacks on Aligned Language Models](https://llm-attacks.org/)
- Survey on LLM Adversarial Attacks: [Adversarial Attacks on LLMs](https://lilianweng.github.io/posts/2023-10-25-adv-attack-llm/)
