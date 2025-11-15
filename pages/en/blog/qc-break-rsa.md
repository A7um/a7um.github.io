---
title: "How Far Are Quantum Computers from Breaking RSA-2048?"
date: 2025-11-14
tags: [quantum-computer, cryptograph]
abstract: >
  In today's digital world, classical public-key cryptography such as RSA-2048 and ECC are the most widely used encryption standards, supporting the underlying trust of network security, financial transactions, and privacy protection. However, this cornerstone is facing the potential threat of quantum computing. In theory, quantum computers can factorize large integers and solve discrete logarithms at speeds far exceeding classical computers, thereby breaking RSA and ECC encryption in a short time. This prospect is both exciting and worrying.The question is: what stage has the development of quantum computers reached? Some optimistically believe that the "countdown" to classical public-key cryptography has already begun; others doubt that truly usable quantum computers are still far away due to manufacturing difficulties. There are various opinions in the market, often optimistic or pessimistic, but the core question always lingers how far are quantum computers from breaking classical public-key cryptography? 
---

In today's digital world, classical public-key cryptography such as RSA-2048 and ECC are the most widely used encryption standards, supporting the underlying trust of network security, financial transactions, and privacy protection. However, this cornerstone is facing the potential threat of quantum computing. In theory, quantum computers can factorize large integers and solve discrete logarithms at speeds far exceeding classical computers, thereby breaking RSA and ECC encryption in a short time. This prospect is both exciting and worrying.

The question is: what stage has the development of quantum computers reached? Some optimistically believe that the "countdown" to classical public-key cryptography has already begun; others doubt that truly usable quantum computers are still far away due to manufacturing difficulties. There are various opinions in the market, often optimistic or pessimistic, but the core question always lingers: how far are quantum computers from breaking classical public-key cryptography? We will attempt to answer this question by dismantling and analyzing the manufacturing bottlenecks and breakthrough hopes of quantum computers.

<!--more-->

## Navigation

We will attempt to answer this question by dismantling and analyzing the manufacturing bottlenecks and breakthrough hopes of quantum computers.
This series is divided into three parts:
1. [Why Can Quantum Computers Accelerate Computation?](#part-1)
2. [How Are Quantum Computers Built?](#part-2)
3. [What Challenges Remain in Building a Quantum Computer Capable of Breaking RSA 2048?](#part-3)

First, to help readers understand the principles of quantum computing, we will introduce necessary quantum mechanics concepts, such as quantum states and entanglement, and explain why quantum computers can achieve acceleration for specific problems; second, to give everyone an intuitive understanding of the form and implementation path of quantum computers, we will analyze their basic construction and focus on dismantling the internal structure of currently fastest-developing and most engineering-feasible superconducting quantum computers; finally, using superconducting quantum computers as an example, we will deeply analyze the bottlenecks they still face in moving toward breaking classical public-key cryptography (RSA-2048), and the potential solutions behind these problems.

Our conclusion is: at the scientific level, there are no "dead ends," and the real challenges are concentrated in engineering implementation. Cooling, control, wiring, energy consumption, and real-time implementation of quantum error correction remain huge challenges, but with the advancement of scale expansion and modular design, these problems are expected to be gradually alleviated. Considering current trends, we agree with the industry's general prediction: million-qubit-level quantum computers are very likely to appear in the 203X years, at which time the defense line of classical public-key cryptography will most likely be breached. This also means that post-quantum migration work must start as early as possible. On the one hand, the "Store Now, Decrypt Later" attack mode already exists in reality - sensitive data, even if stolen today, may be decrypted by quantum computing in the future; on the other hand, the migration of cryptographic systems itself is a huge project involving algorithm replacement, system transformation, standard compliance, and ecosystem adaptation, usually requiring many years to complete. If we wait until quantum computers are truly about to emerge before taking action, it is often too late.

This article is also published on "Science Popularization China" and ["Tencent Post-Quantum Cryptography Theme Site"](https://pqc.tencent.com/zh). By the way, this website also has high-quality content such as post-quantum migration guides, industry trend tracking, post-quantum cryptography standards, and algorithm performance evaluation. Welcome to follow! 👏

<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@4/tex-mml-chtml.js"></script>

-----

<a name="part-1"> </a> 

# Part 1: Why Can Quantum Computers Accelerate Computation?

The core advantage of quantum computers lies in their utilization of **quantum superposition** and **quantum entanglement**. To understand their acceleration of computation, we first need to understand the fundamental characteristics of quantum physics—superposition states, collapse, and quantum entanglement.

Note: To make it understandable for readers unfamiliar with mathematics or physics, this section will try to avoid using mathematical formulas, which may result in some inaccuracies in details, but will not affect overall understanding. For readers with a certain mathematical foundation, you can read alongside [Appendix 1](#appendix-1), which provides a more intuitive explanation of phenomena such as superposition states, collapse, and entanglement in mathematical form.

## Superposition States and Collapse

In classical physics, the state of a system (such as position, velocity) is determined at any moment; in quantum mechanics, the situation for particles is different. Before being measured, a physical quantity of a particle (such as position, momentum, spin, energy level, etc.) is not in a specific value, but in a superposition state that simultaneously contains all possible results. Only when measured does this superposition state instantly become a fixed value according to some probability.

A simple example: imagine two small boxes, and a particle can only appear in one of them. According to classical intuition, it is either in the left box or in the right box, never in two places at the same time. However, quantum experiments have found that before measurement, the particle is not already in the left or right, but in a state that simultaneously "contains both left and right possibilities." Only when we actually measure it does the particle appear in one of the boxes. This process is called collapse. During collapse, each possible state corresponds to a probability (the probabilities must sum to 1, and the specific probability distribution is one of the properties of the superposition state). For example, a particle might be in the following superposition state:
- Probability of appearing on the left is 70%
- Probability of appearing on the right is 30%

This may sound incredible, but the existence of superposition states has long been verified through experiments. A classic example is the double-slit interference experiment with electrons. Interested readers can further look up related experiments.

<center><img src='/static/qc-break-rsa_zh/quantum-superposition.png' /></center>
<center>Figure: Comparison of classical physical states and quantum superposition states. The color of quantum superposition states represents their probability of appearing during measurement.</center>

Based on this principle, quantum computers select two clearly distinguishable results from a physical system as the basic unit of information. For example, we can specify "particle in the left box" as 0 and "particle in the right box" as 1. In this way, before being measured, a quantum bit is not simply 0 or 1, but simultaneously contains both possibilities. When measurement occurs, it will be determined as one of them. This means that quantum bits can simultaneously carry information of both 0 and 1 in superposition form before measurement, which is the fundamental characteristic that distinguishes them from classical bits.

## Quantum Entanglement

After understanding that a single physical quantity can simultaneously exist in multiple possibilities through superposition, we can further discuss quantum entanglement. Quantum entanglement is a quantum correlation phenomenon beyond classical intuition. When certain properties (such as their positions) of two or more particles become entangled, these properties are no longer independent of each other but form an inseparable whole.

An example: imagine two identical small boxes, one on the left and one on the right. We now place two particles, numbered 1 and 2. According to classical intuition, there are four possible situations, each with a certain probability:
- Both particles on the left (recorded as LL)
- Both on the right (recorded as RR)
- 1 on the left, 2 on the right (recorded as LR)
- 1 on the right, 2 on the left (recorded as RL)

Classical physics would think that the particles must be in one of these definite combinations; we just don't know which one temporarily.

However, in quantum physics, if the positions of two particles have undergone "complementary value entanglement," that is, the situation we mentioned earlier where "the two particles must be in different boxes," then the situation is completely different. Before measurement, they are not already fixed in a certain combination but are in an overall superposition state. In this state, only two possibilities can exist simultaneously:
- 1 on the left, 2 on the right (LR)
- 1 on the right, 2 on the left (RL)

When we actually measure, the system will instantly "collapse" to one of them: either LR or RL. Each situation has a corresponding probability (the probabilities do not have to be equal; the probability distribution is an inherent property of the entangled state). At the same time, the probability of LL and RR results is zero. It can be seen that quantum entanglement is actually an extension of superposition states in multi-dimensional bases. Quantum entanglement has also been verified through physical experiments. Interested readers can further look up related materials (keywords: EPR paradox, Bell inequality).

<center><img src='/static/qc-break-rsa_zh/quantum-entanglement.png' /></center>
<center>Figure: Comparison between classical particle combinations and particle entanglement</center>

Applying this principle to quantum bits (for example, we consider L as 0 and R as 1), we can prepare an entangled state where "the values of two bits must be different." In this state, before measurement, the two bits are not definitely in "01" or "10" but are in a superposition of these two possibilities. When measurement occurs, the system will instantly collapse to a definite result: either "01" or "10." At the same time, the two combinations "00" and "11" will never appear; their probability is zero.

## Using Superposition and Entanglement to Accelerate Computation

Superposition gives quantum bits the ability to simultaneously exist in multiple states before measurement, and entanglement allows quantum bits to form non-classical strong correlations, which are indispensable core resources in many quantum algorithms and quantum error correction.

Here, we give an intuitive example to help understand. Suppose we have a system composed of \\(n\\) quantum bits to represent an input variable \\(x\\). Due to the superposition principle, the state of \\(x\\) can simultaneously cover all possible values from \\(0\\) to \\(2^n-1\\), not just one specific number. When we input such a quantum state into function \\(f(x)\\), the output will also become a superposition state of all possible input corresponding results.

If we want to find the value of \\(x\\) that satisfies \\(f(x)=c\\), we can use carefully designed quantum algorithms (involving the use of mechanisms such as **quantum entanglement** and **quantum interference**) to enhance the probability amplitude corresponding to the correct result while weakening the probability amplitude of incorrect results. In this way, during final measurement, we can obtain the correct answer with a higher probability. It should be emphasized that this process of "amplifying the probability of correct solutions" is one of the core ideas of quantum algorithms.

<center><img src='/static/qc-break-rsa_zh/quantum-computing-principles.png' /></center>
<center>Figure: The core idea of quantum computing—achieving parallel computation through superposition, and amplifying the probability of correct solutions through entanglement and interference</center>

Note: When mentioning quantum interference, we actually assume that quantum states can be represented in wave form. To accommodate readers unfamiliar with mathematics or physics, I did not elaborate on this point. If readers are interested in "why microscopic physical quantities can be described in wave form," please refer to [Appendix 1](#appendix-1).

<center><img src='/static/qc-break-rsa_zh/wave-interference.png' /></center>
<center>Figure: Interference is the superposition effect of waves. When the peaks of two sine waves coincide, constructive interference occurs, and the amplitude after superposition increases; conversely, destructive interference occurs, and the amplitude decreases. The noise-canceling headphones we are familiar with use destructive interference to cancel noise. Quantum computing can also amplify the probability amplitude of correct answers through constructive interference and reduce the amplitude of incorrect answers through destructive interference.</center>

Of course, real quantum algorithms are far more complex than this intuitive description. Here we only provide a simplified explanation and do not involve specific algorithm details for now. If readers want to further understand why quantum algorithms pose a potential threat to classical cryptographic systems, please refer to [Appendix 2](#appendix-2).

## Quantum Computing's Acceleration Effects on Different Problems

The main sources of acceleration brought by quantum computers are:
- Superposition states, meaning \\(n\\) quantum bits can simultaneously represent \\(2^n\\) states, equivalent to processing all possibilities in parallel at once.
- Entanglement, through strong correlation between quantum bits, allows interference between different states, thereby effectively extracting useful information and amplifying correct answers.

This acceleration manifests differently for different types of problems. When suitable quantum algorithms are available:
- **Structured problems** (such as integer factorization): Quantum algorithms can utilize their structure (such as periodic structure) to quickly extract answers through certain algorithms (such as quantum Fourier transform), thereby achieving **exponential acceleration**.
- **Unstructured problems** (such as finding \\(x\\) that satisfies \\(f(x)=c\\)): Due to the lack of patterns to exploit, we can only rely on continuous \\(\sqrt{N}\\) times of interference to amplify the probability amplitude of the correct answer, so the number of computations can only be reduced from the classical \\(N\\) times to \\(\sqrt{N}\\) times, corresponding to **square root level acceleration**.

-----

<a name="part-2"> </a>

# Part 2: How Are Quantum Computers Built?

## Physical Implementation Methods of Quantum Bits

Quantum bits are essentially constructed from states in the physical world. Depending on the source of physical states used, quantum computer construction methods can be divided into two categories:

The first type of quantum computer is based on microscopic particles, such as ions, photons, or atoms, computing by manipulating and measuring their quantum states. Microscopic particles of the same type are completely identical in physical properties, which plays an important role in realizing multi-particle quantum interference and entanglement. At the same time, these particles can maintain high quantum state purity, low error rates, and long coherence times (i.e., the time quantum states can be maintained) under well-isolated conditions. However, precise manipulation of these particles is still very difficult at current technical levels, and the time required for operations is usually long.

The second type is quantum computers based on artificial structures, such as superconducting circuits and quantum dots, using the macroscopic manifestation of microscopic states of artificial structures as quantum states. The advantage of this approach is that it is easy to manufacture and operate, and can be expanded using modern semiconductor technology. However, defects in artificial materials are a major challenge. Unlike natural particles, each artificial structure has subtle differences, which may introduce additional noise or errors, affecting the stability of quantum states. However, compared to microscopic particles, quantum bits of artificial structures are easier to measure and control, and are more feasible in engineering.

<center><img src='/static/qc-break-rsa_zh/qubit-two-types.png' /></center>

<center>Figure: Two major construction methods of quantum computers</center>

Currently, superconducting quantum computing is considered one of the most mature and promising directions because it shows excellent performance in operating speed and integration, and its technological development is relatively rapid. Therefore, we will focus on introducing superconducting quantum computers as an example.

## Construction Principles of Superconducting Quantum Bits

Specifically for superconducting quantum computers, the state of quantum bits comes from the "energy level" of its core component, the "Josephson junction." A Josephson junction consists of two superconductors sandwiching a nanometer-scale insulator. Energy levels are the energy values that a physical system can have, characterized by being discrete and fixed. The system's energy can only be at one of these specific values, such as E₀, E₁, etc., and cannot vary continuously. This phenomenon is one of the fundamental characteristics of quantum mechanics. The lowest energy level E₀ is usually called the "ground state," and higher energy levels (such as E₁) are called "excited states." The two basic states of a quantum bit—0 and 1—correspond to the system's ground state E₀ and the first excited state E₁, respectively.

<center><img src='/static/qc-break-rsa_zh/josephson-junction.png' /></center>
<center>Figure: Josephson junction construction principle</center>

By applying microwave signals of specific frequencies to the Josephson junction (microwaves are a type of electromagnetic wave that can transmit energy. For example, microwave ovens use microwaves of specific frequencies to drive polar molecules such as water molecules in food to rotate and vibrate rapidly, causing them to interact and generate heat, thereby heating food), energy can be injected into the system, causing the quantum bit to jump from the lower energy level E₀ to the higher energy level E₁, or return from E₁ to E₀ by releasing energy. This precise control of energy level transitions is key to implementing basic logical operations in quantum computing. Furthermore, if only a "half pulse" of microwave signal is applied—that is, the quantum bit is not completely driven from E₀ to E₁, but stopped exactly in the middle state—then the quantum bit will be in a superposition state of E₀ and E₁. In summary, we can precisely control the state of quantum bits by adjusting the frequency, intensity, and duration of microwaves.

<center><img src='/static/qc-break-rsa_zh/quantum-jump.png' /></center>
<center>Figure: Energy level transition and control of superconducting quantum bits. A complete pulse provides exactly the right energy to make the quantum bit completely transition from ground state E₀ to excited state E₁, realizing the |0⟩ → |1⟩ conversion. A half pulse only provides partial energy, placing the quantum bit in a superposition state of E₀ and E₁, i.e., simultaneously in a quantum superposition of |0⟩ and |1⟩. By adjusting the frequency, intensity, and duration of microwaves, the state of quantum bits can be precisely controlled</center>

Since the energy difference between the energy levels of superconducting quantum bits is extremely small, quantum states are extremely sensitive to disturbances from the external environment. Even very slight thermal noise, electromagnetic waves, or radiation interference can cause decoherence of quantum states (i.e., destruction of quantum states), preventing quantum bits from working properly. To reduce these interferences, superconducting quantum computers must operate in extremely low-temperature environments close to absolute zero (about 10 millikelvin (mK), only 0.01 degrees higher than absolute zero -273.15 °C, already the lowest continuous temperature humans can achieve), and use special materials and carefully designed shielding, filtering, and attenuation measures in connecting circuits to maintain energy level stability and manipulation precision as much as possible.

## From Single Bit to the "System Architecture" of Superconducting Quantum Computing

To build a practically operational superconducting quantum computer, not only quantum bits themselves are needed, but also a complete support system: refrigeration and shielding systems to protect quantum states, control systems to manipulate quantum bits, and error correction systems to correct errors in quantum systems in real-time. Among these systems, the error correction system is particularly critical. This is because the reliability of quantum computing faces two fundamental challenges:
- Insufficient coherence time: That is, the duration a quantum bit can maintain quantum properties such as superposition and entanglement without being destroyed by the environment. Therefore, to use quantum bits for computation, the coherence time of quantum bits must be longer than the time required for computation. Although measures such as refrigeration and shielding can extend coherence time, they are still difficult to meet the demands of complex operations.
- Insufficient gate fidelity: Quantum gates are not fixed gate circuits like classical bits, but are implemented through real-time manipulation by external control signals. The closeness of the actual effect of quantum gate operations to the ideal effect is the gate fidelity. However, even if the fidelity of a single gate operation is very high (such as 99.9%), after performing thousands or even millions of operations, errors will continue to accumulate, ultimately destroying computational results.

Next, we will introduce each core component of superconducting quantum computers in detail:

### Quantum Chip

Using traditional semiconductor processes to fabricate Josephson junctions on silicon wafers to form quantum bits, with packaging to lead out interfaces for control and measurement.

<center><img src='/static/qc-break-rsa_zh/quantum-chip.png' width='50%' /></center>
<center>Figure: Schematic diagram of a quantum chip (also called quantum processor) with 20 superconducting quantum bits. You can see that each quantum bit needs to lead out multiple cables (such as control lines, readout lines), and there need to be couplers (similar to switches) interconnecting between quantum bits</center>

### Refrigeration System

Using a dilution refrigerator (a cooling device that achieves ultra-low temperatures using a helium-3/helium-4 mixture, currently the refrigeration device that humans can continuously operate and reach the lowest temperature, capable of lowering temperature to about 10 mK or even lower) to cool the quantum chip and its connecting wires to near absolute zero, while configuring attenuators and filters to "purify" control signals, and configuring shielding devices to shield external noise, to eliminate external noise interference as much as possible.

<center><img src='/static/qc-break-rsa_zh/cooling-system.webp' /></center>
<center>Figure: IBM Q quantum computer refrigeration system structure. The entire structure will be placed in a dilution refrigerator. As you can see, it includes microwave guide wires for controlling and reading quantum bits; input signals pass through multi-stage attenuators to reduce noise, while output signals are amplified through low-noise amplifiers; it is also equipped with multi-layer shielding devices to isolate external radiation, and uses coaxial cables with carefully selected materials to ensure reliable transmission at low temperatures and minimize thermal load. From the top to the bottom of the system, temperature decreases gradually: the uppermost layer is at room temperature, while the bottom layer can reach an extremely low temperature environment of about 10 mK, providing conditions for stable operation of quantum bits.</center>

### Quantum Bit Control System

Converting quantum operation instructions issued by classical computers into high-precision microwave pulses for driving, manipulating, and reading quantum bits, typically including devices such as microwave generators, mixers, amplifiers, and isolators.

<center><img src='/static/qc-break-rsa_zh/qubit-control.png' /></center>
<center><p>Figure: The quantum bit control system receives digital control signals from classical computers and converts them into microwave pulses capable of precisely manipulating quantum bits through a series of precision microwave devices. The core of the system lies in maintaining extremely high signal purity and timing precision to ensure precise manipulation of quantum states. Converting classical digital signals into high-precision microwave pulses for driving, manipulating, and reading quantum bits.<p></center>

### Quantum Error Correction System

Through redundant encoding and real-time feedback, detecting and correcting errors caused by decoherence and noise during quantum computation, thereby extending coherence time and improving gate fidelity. For example, the currently most commonly used surface code error correction scheme encodes a logical quantum bit into a two-dimensional quantum bit array, continuously measuring correlations between adjacent bits to discover and correct errors, thereby extending the life of logical bits when the hardware error rate is below the threshold.

<center><img src='/static/qc-break-rsa_zh/quantum-error-correction.png' /></center>
<center>Figure: The quantum error correction system is a classical-quantum hybrid system. The entire error correction loop must complete error correction in real-time, with error correction time far less than decoherence time. FPGA's low-latency processing combined with CPU/GPU's powerful computing power, along with precise timing synchronization, ensures error correction is completed before quantum information is lost.</center>

### Overall Architecture

From the figure below, we can roughly understand the overall architecture of quantum computers.

<center><img src='/static/qc-break-rsa_zh/quantum-computer-architecture.png' /></center>
<center>Figure: IBM Q quantum computer architecture diagram. We can find the components we described in the figure.</center>

## Building Quantum Computers Requires Combining Science and Engineering

The construction of quantum computers is both physics and engineering. Particle-based solutions are purer at the physical level but difficult to implement in engineering; artificial structure-based solutions (especially superconducting quantum bits) are more scalable in engineering but need to overcome noise and decoherence problems. A complete superconducting quantum computer is essentially a complex combination of quantum chip + dilution refrigerator + control electronics + quantum error correction system. It is both a physical experimental device and a highly engineered system. It is precisely because of this "from physics to system" complete chain that superconducting quantum computers have become the most promising solution to cross the practical threshold first.

-----

<a name="part-3"> </a>

# Part 3: What Challenges Remain in Building a Quantum Computer Capable of Breaking RSA 2048?

Currently, the quantum bit scale of relatively mature superconducting quantum computers is mostly in the hundreds. As mentioned in Part 1, quantum computers can provide exponential acceleration in integer factorization. Shor's algorithm requires approximately 2N quantum bits for computation to factorize an N-bit integer, plus auxiliary registers and additional overhead required for operations. To break RSA-2048, the overall scale would be about several thousand quantum bits.

It sounds like we're not far from success, right? Actually not. To make quantum computing successfully complete the break, as mentioned earlier, the coherence time of quantum bits must be longer than the time required to complete all necessary operations. However, currently the coherence time of superconducting quantum bits is usually only tens to hundreds of microseconds, and quantum gate operation time is in the tens to hundreds of nanoseconds range, while Shor's algorithm requires 10¹² order of magnitude quantum gate operations, so the computation time will far exceed the coherence time of quantum bits. Even if operations can be completed within coherence time, they will be limited by gate fidelity. Even if the fidelity of a single gate is as high as 99.9%, after 10¹² operations, minute errors will continue to accumulate, ultimately destroying computational results.

Therefore, we must rely on quantum error correction to break through these physical bottlenecks. Taking surface code as an example, by encoding a large number of physical quantum bits into one logical quantum bit, it effectively extends "usable coherence time" and offsets cumulative errors in gate operations. Based on current error rates and error correction schemes, one logical quantum bit typically requires thousands of physical quantum bits. In other words, to obtain thousands of logical quantum bits to run Shor's algorithm, the total number of physical quantum bits actually required will reach the million level.

Next, we will introduce in detail the technical obstacles that each core component of quantum computers needs to cross to expand the number of superconducting quantum bits from hundreds to millions.

## Quantum Chip

The quantum chip, that is, the chip where quantum bits (Josephson junctions) are placed, is also called a quantum processor. To construct chips with more quantum bits, three main difficulties will be encountered: wiring problems, crosstalk problems, and semiconductor yield problems.

### Wiring Problem

Since each quantum bit needs to lead out multiple cables (such as control lines, readout lines), and there also need to be couplers (similar to switches) interconnecting between quantum bits. On a two-dimensional chip, when the number of quantum bits increases, wiring complexity will **increase nonlinearly**. Especially when high connectivity needs to be achieved, control lines for bits in the central area must bypass peripheral bits, causing chip area to increase dramatically.

<center><img src='/static/qc-break-rsa_zh/wiring.png' /></center>
<center>Figure: As the number of quantum bits increases, wiring complexity grows nonlinearly</center>

### Crosstalk Problem

Crosstalk refers to mutual interference between quantum bits, which causes quantum state decoherence and increases nonlinearly with the number of bits. Common crosstalk can be divided into:
- Classical crosstalk: The control signal frequencies of quantum bits are too close, causing control interference. (Frequency refers to the number of periods a wave completes per second. In quantum computing, each quantum bit is controlled by microwave signals of different frequencies, thereby achieving precise operation and regulation)
- Quantum crosstalk: Bit coupling that should be turned off is not completely shut down; (analogous to classical circuits, current still flows after the switch is opened)
- Global crosstalk: Crosstalk from unknown physical processes in the external environment, such as cosmic rays, phonon propagation, etc.

To avoid crosstalk, on one hand, larger isolation areas or carefully designed shielding structures may be needed, and on the other hand, coupler performance can also be optimized at the device level to allow bit coupling switches to shut down more thoroughly. In addition, improving the measurement and control system, especially frequency allocation optimization, also helps reduce crosstalk when executing two-bit gates in parallel.

<center><img src='/static/qc-break-rsa_zh/crosstalk.png' /></center>
<center>Figure: Crosstalk increases nonlinearly with the number of quantum bits, seriously affecting quantum state coherence.</center>

### Device Yield Problem

If looking only at area, the area of quantum chips should be linearly related to the number of quantum bits. However, due to the need to handle wiring and crosstalk problems, actual chip area often approaches square growth with the number of quantum bits. In other words, the more quantum bits, the more nonlinearly the chip area expands.

More troublesome is that quantum bits are extremely sensitive to defects, and even a 1% failure rate will make the entire system unusable. If there are defects inside or on the surface of the chip, they may couple with quantum bits, reducing their coherence time. In the field of micro-nano processing, there is a basic rule: the larger the chip area, the lower the yield, and the manufacturing difficulty of large-area chips increases exponentially. For superconducting quantum chips, although their manufacturing process can borrow mature equipment and process flows from the semiconductor industry, the extreme sensitivity of quantum bits to manufacturing defects makes the yield problem a huge challenge.

<center><img src='/static/qc-break-rsa_zh/device-yield.png' /></center>
<center>Figure: Area grows with the number of quantum bits as N², while yield decreases exponentially with area. Probability values in the figure are for demonstration only, not real values.</center>

### Hope on the Horizon: Modular Design and Inter-Chip Interconnection

The problems of wiring, crosstalk, and yield all worsen nonlinearly as the number of quantum bits increases. Therefore, directly constructing a million quantum bits on a single chip is almost impossible.

So a new idea emerged: first construct small chip (chiplet) modules with thousands of physical quantum bits (so that a reliable logical quantum bit can be formed), then connect these small chips through inter-chip interconnection technology. In this way, the engineering challenge of a single chip is only to expand from hundreds to thousands, greatly reducing difficulty and becoming more feasible.

However, this idea also brings new problems. Quantum bits are very fragile and must work in low-temperature environments around 10 millikelvin. If each chiplet is placed in an independent dilution refrigerator, then to achieve interconnection between chiplets, signal lines would need to be led out from the low-temperature environment of one refrigerator to room temperature, then enter the low-temperature environment of another refrigerator.

This "low temperature ↔ room temperature ↔ low temperature" signal transmission path will introduce large thermal loads and noise, thereby destroying the state of quantum bits. If all chiplets are placed in the same dilution refrigerator, then we need an extremely powerful dilution refrigerator to accommodate thousands of chiplets, and manufacturing such a large-scale dilution refrigerator is itself a new challenge.

<center><img src='/static/qc-break-rsa_zh/chiplet-interconnection.png' /></center>
<center>Figure: Chiplet interconnection across dilution refrigerators introduces additional thermal noise. Note that the actual interconnection topology is not necessarily direct connection between adjacent Chiplets pairwise. The adjacent interconnection method shown in the figure is for demonstration only.</center>

<center><img src='/static/qc-break-rsa_zh/chiplets-in-same-refrigerator.png' /></center>
<center>Figure: Multiple Chiplets are placed in the same dilution refrigerator and directly interconnected in a low-temperature environment. This centralized solution means needing an ultra-high-power dilution refrigerator to accommodate and maintain the working temperature of a large number of Chiplets. Note that the actual interconnection topology is not necessarily direct connection between adjacent Chiplets pairwise. The adjacent interconnection method shown in the figure is for demonstration only.</center>

Therefore, in the future, we either need to find new ways to suppress noise in cross-refrigerator interconnection, or we need to make breakthroughs in scaling up dilution refrigerators. From the current scientific and engineering status, the latter—developing larger power and larger space low-temperature dilution refrigerators—seems to be a more feasible direction.

### Summary

If adopting the chiplet design + inter-chip interconnection scheme, then the technical gap that needs to be crossed at the quantum chip level is how to expand single-chip quantum bits from hundreds to thousands.

The good news is that semiconductors are already an "illuminated tech tree," and related processes continue to improve. For example, 3D stacking processes in advanced packaging can be borrowed to manufacture quantum chips, thereby improving wiring density and interconnection capability. At the same time, optimization of superconducting material processes, multiplexing design, and improvements in chip architecture design (such as more efficient couplers, more reasonable frequency planning) will all help us break through this barrier.

Therefore, the stage of expanding a single small chip from hundreds to thousands of **physical quantum bits**, although not easy in difficulty, this step is mainly an engineering bottleneck, and overall looks relatively optimistic. Currently, [IBM has already built a single chip with 1000 physical quantum bits](https://www.nature.com/articles/d41586-023-03854-1), although due to the large chip area, it will inevitably face challenges in yield and reliability of quantum bits within the chip during mass production.

## Refrigeration System

Since the energy level difference of superconducting quantum bits is very small, quantum states are extremely susceptible to disturbances from the external environment and decohere. Currently known main interference factors include:
- Passive thermal sources: Although quantum bits are in an environment close to absolute zero, they must be connected to room-temperature electronic equipment through wires. Wires act like a "thermal bridge," bringing heat from high-temperature environments to low-temperature areas.
- Active thermal sources: Manipulating quantum bits requires sending microwave pulses, which are transmitted along wires. During transmission and attenuation, energy always converts to heat, which accumulates and heats the environment.
- Thermal radiation: Even if wires and materials are isolated, there is still electromagnetic radiation coupling between quantum chips and the outside world. High-temperature environments will "radiate heat" to low-temperature chips.

<center><img src='/static/qc-break-rsa_zh/thermal-interference.png' /></center>
<center>Figure: Three major thermal interference sources for quantum bits</center>

To isolate these effects as much as possible, current practice is:
- Use materials with appropriate thermal and electrical conductivity to make wires;
- Add filters and attenuators in signal paths to weaken unnecessary frequency bands and dissipated energy from control signal transmission;
- Use dilution refrigerators for staged cooling (not directly cooling from room temperature to 10 mK, but sequentially through room temperature → 50 K → 4 K → 1 K → 100 mK → 10 mK), progressively shielding thermal sources.

<center><img src='/static/qc-break-rsa_zh/cooling-layers.png' /></center>
<center>Figure: Dilution refrigerator staged cooling system. The roles of staged cooling are (1) Each temperature stage acts as a thermal buffer, gradually isolating the thermal load of high-temperature environments; (2) Filters filter out unnecessary frequency components, reducing noise interference; (3) Attenuators reduce signal strength while absorbing excess energy, preventing heating of low-temperature areas; (4) Thermal shielding layers block radiation from upper levels, protecting lower-level low-temperature environments</center>

This method can currently roughly support hundreds of physical quantum bits. However, if we want to build million-level quantum bits (for example, composed of thousands of chiplets, each with thousands of bits), the problem becomes apparent: each quantum bit requires corresponding wires, attenuators, and filters, the number of which increases approximately linearly with bits. Although the thermal leakage of a single wire is not large, when the number of wires and filters expands to the million level, the accumulated thermal load will far exceed the refrigerator's limit. Of course, to address this challenge, besides needing to develop more powerful dilution refrigerators, we also need to explore how to use multiplexing technology, low-temperature CMOS circuits, and low-temperature superconducting electronics to reduce wiring and energy consumption overhead.

In short, the cooling power and physical space of existing dilution refrigerators are seriously insufficient. To support a million-bit system, the refrigerator's power needs to increase by at least a million times or more. But such ultra-high-power, ultra-large-volume dilution refrigerators do not yet exist.

<center><img src='/static/qc-break-rsa_zh/cooling-challenge.png' /></center>
<center>Figure: From hundreds to millions of bits, refrigeration system scalability challenges</center>

If adopting a "chiplet design" + "low-temperature inter-chip interconnection" scheme, then the refrigeration system is a major engineering hurdle that must be crossed, requiring enormous R&D investment (likely in the tens of billions of dollars range).

## Quantum Bit Control System

As mentioned earlier, each superconducting quantum bit needs to be controlled using microwave signals, and different bits must be assigned different control frequencies. As the number of quantum bits expands from hundreds to millions, the control system will face several obvious challenges:

- Frequency crowding: The microwave spectrum range is limited. As the number of bits increases, frequency intervals are forced to decrease. When adjacent frequencies are too close, control signals may interfere with each other, causing crosstalk problems.

<center><img src='/static/qc-break-rsa_zh/signal-interference.png' /></center>
<center>Figure: When adjacent frequencies are too close, control signals may interfere with each other, causing crosstalk problems.</center>

- Increased precision requirements: Narrower frequency bands mean control signals must be more stable, otherwise they will "overflow" to adjacent bits. Requirements for frequency stability and phase noise become more stringent.

<center><img src='/static/qc-break-rsa_zh/signal-stability-control.png' /></center>
<center>Figure: After frequency bands narrow, requirements for control signal frequency stability and phase noise increase significantly. Even minor frequency drift may cause signals to overflow to adjacent quantum bits</center>

- Soaring control complexity: Each quantum bit requires independent pulse control (amplitude, phase, timing). If there are a million quantum bits, there must be a million independent control channels. Currently, the hardware cost per channel is approximately ¥100,000/channel, with the long-term goal of reducing it to ¥1,000/channel, otherwise the cost will be unbearable.

<center><img src='/static/qc-break-rsa_zh/million-channels.png' /></center>
<center>Figure: If there are a million quantum bits, there must be a million independent control channels</center>

These problems are essentially engineering bottlenecks. They have already appeared in small-scale systems, and complexity increases linearly as scale expands.

However, the challenges in this direction are generally considered relatively optimistic compared to other issues in the industry, mainly for the following reasons:

- Pattern of frequency crowding: Experiments show that within the range of dozens of bits (approximately within 60 bits), the complexity of frequency allocation increases rapidly, but as the number of bits further increases, frequency reuse and clever bit layout can make complexity manageable. Therefore, "frequency crowding" is not necessarily an insurmountable hard barrier.
- Limited gate precision requirements: Quantum computing does not require infinite precision. As long as two-bit gate fidelity can stabilize around 99.99%, it is sufficient to support quantum error correction. Although this still requires very high noise control for the control system, it is achievable with existing semiconductor technology. The only issue is that high-speed digital-to-analog converters (DACs) capable of achieving this precision are currently too expensive. Whether costs can be reduced through large-scale manufacturing remains to be seen.
- Potential for hardware cost optimization: Current control uses superconducting coaxial cables, adapters, attenuators, and filters, which are expensive and bulky. A potential direction is to borrow flexible substrate processes from the semiconductor industry to directly mass-produce integrated low-temperature wiring on low-cost materials, thereby significantly reducing cost and volume.

In summary, the control system is another engineering bottleneck that must be crossed: million-level quantum bits require a million independent control channels, with frequency allocation, signal precision, and cost reduction all being key difficulties. Although relatively more optimistic compared to other issues, it still requires long-term engineering investment and technological iteration.

## Error Correction System

To make quantum bit and gate fidelity meet the requirements for completing large-scale computations like factoring RSA, we must rely on **quantum error correction**: using thousands of physical bits to form 1 logical bit.

The theoretical framework of quantum error correction is already mature and can significantly improve the coherence time and gate fidelity of logical bits. For example, Google's Willow project demonstrated obtaining more stable logical bits through error correction methods.

In the Willow processor, a logical quantum bit is not directly represented by a single physical bit but is jointly encoded by a two-dimensional physical bit array. The array contains two types of bits:

- Data bits: Used to carry logical quantum states;
- Auxiliary bits: Through periodic operations to detect whether errors have occurred between data bits.

The measurement results of these auxiliary bits do not directly reveal the logical state itself but can reflect whether errors such as bit flips or phase flips have occurred in the system. Combined with decoding algorithms, the system can determine where errors occurred and make corrections. In Willow's experiments, researchers verified this key characteristic on hardware for the first time: when the physical bit error rate drops below the threshold, theoretically, as long as engineering allows, the effective coherence time of logical quantum bits can be continuously extended by continuously increasing encoding scale, and the fidelity of logical gates can be continuously improved. In other words, the ultimate limitations on coherence time and gate fidelity mainly come from engineering resources, not fundamental physical laws.

<center><img src='/static/qc-break-rsa_zh/logical-qubit.png' /></center>
<center>Figure: Multiple easily disturbed physical bits can form a stable logical bit. Theoretically, by expanding the scale of physical quantum bits used for error correction, coherence time can be extended to any duration required to complete large-scale quantum computing.</center>

However, in engineering implementation, decoding algorithms must be real-time: if errors accumulate too quickly, they will exceed the recoverable range. As the number of bits increases, error correction overhead grows nonlinearly, imposing extremely high requirements on classical hardware computing power and latency. Fortunately, error correction computation itself can be highly parallel, so theoretically bottlenecks can be alleviated by increasing computing power (i.e., "throwing money at it").

The challenge is not only at the physical level but also in software-hardware integrated engineering: since quantum bits continuously generate random errors that cannot be known before operation, circuits must dynamically adjust subsequent operations based on error information detected on-site. At the same time, the error correction system must also implement real-time scheduling and calibration of logical bits and complete parallel decoding under extremely low latency. These requirements stacked together make fault-tolerant quantum computing not only a hardware challenge but also a system engineering project of enormous scale and extremely high complexity.

<center><img src='/static/qc-break-rsa_zh/qec-challenge.png' /></center>
<center>Figure: Quantum error correction is not only a physics problem but also an extremely challenging system engineering project: requiring completion of error detection, parallel decoding, and real-time correction within microseconds. Computing power requirements grow nonlinearly with system scale, but can be solved by increasing hardware resources ("throwing money").</center>

In summary, the quantum error correction system is a threshold that must be crossed: it requires thousands of physical bits to form 1 logical bit and relies on real-time, parallel error correction and dynamic scheduling, imposing extremely high requirements on software-hardware integration and representing an extremely challenging system engineering project. However, the entire process has no scientific limitations that cannot be solved—it is more a challenge of system engineering.

## Quantum Computers Capable of Breaking RSA-2048 Will Likely Appear in the 203X Years

In summary, to manufacture a million-quantum-bit computer capable of breaking RSA-2048, the scientific challenge lies in the unavoidability of decoherence and gate errors, but quantum error correction theory has provided a clear solution path; the real difficulty is at the engineering level, including cooling, control, wiring, energy consumption, and real-time implementation of quantum error correction. As scale expands, these problems will show nonlinear amplification, especially crosstalk, error correction overhead, and energy consumption. However, after a certain scale, modular design and inter-chip interconnection can make complexity enter a regionally linear phase. Overall, there are no scientific "dead ends," but engineering challenges are extremely large, requiring long-term accumulation and huge investment. Currently, the industry generally expects such quantum computers to appear in the 203X years with high probability, and we agree with this judgment.

-----

<a name="appendix-1"> </a>

## Appendix 1: Mathematical Expression of Superposition States and Entanglement

### Vector Expression of Superposition States and Collapse

In quantum mechanics, for a single quantum state, we can express it in vector form:

$$ |\psi\rangle = \alpha |S_0\rangle + \beta |S_1\rangle $$

Where:
- \\(|S_0\rangle\\) and \\(|S_1\rangle\\) are two possible states of the quantum system;
- \\(\alpha\\) and \\(\beta\\) are called complex probability amplitudes, whose modulus squared gives the probability of obtaining the corresponding state during measurement, and they satisfy \\(|\alpha|^2+|\beta|^2=1\\).

Quantum computers select two distinguishable physical quantum states from a physical system as information carriers, denoted as \\(|0\rangle\\) and \\(|1\rangle\\), respectively. Therefore, the state of a quantum bit (qubit) can be written as:

$$ |\psi\rangle = \alpha |0\rangle + \beta |1\rangle $$

### Vector Expression of Quantum Entanglement

If two bits undergo **"complementary value entanglement,"** that is, the situation we mentioned earlier where "the values of two bits must be different," then the system's state is:

$$ |\psi\rangle = \alpha |01\rangle + \beta |10\rangle $$

Where \\(\alpha\\) and \\(\beta\\) are complex probability amplitudes satisfying the normalization condition \\(|\alpha|^2+|\beta|^2=1\\).

This means: the probability of measurement result "01" is \\(|\alpha|^2\\), the probability of measurement result "10" is \\(|\beta|^2\\), while the probabilities of "00" and "11" are strictly zero. It can be seen that quantum entanglement is actually an extension of superposition states in multi-dimensional bases.

### Wave Function Expression of Quantum States

Quantum states can also be described in wave form, with the modulus square of the wave function giving the probability of collapsing to a specific state. Taking a particle confined in a one-dimensional box (with impassable walls at both ends) as an example, the particle's waves reflect at both ends and superpose on each other (similar to sound echoing between two walls), and the wave function manifests as a standing wave.

$$ \psi_n(x,t) = \sqrt{\frac{2}{L}} \sin\left(\frac{n\pi x}{L}\right) e^{-i\omega_n t} $$

Where \\(t\\) is time, \\(x\\) is the particle's position, \\(L\\) is the box length (range of particle motion), \\(n\\) is the quantum number (1,2,3..., determining how many peaks and troughs the wave function has), \\(k = \frac{n\pi}{L}\\) is the wave number (i.e., spatial frequency), \\(\lambda = \frac{2\pi}{k} = \frac{2L}{n}\\) is the wavelength (i.e., spatial period), \\(\omega\\) is the angular frequency, and the wave's temporal frequency \\(f = \frac{\omega}{2\pi}\\). The probability of the particle appearing at position \\(x\\) at time \\(t\\) is \\(|\psi(x,t)|^2\\). The passage of time only adds a string of rotating phase factors to the entire wave function, not affecting the probability distribution.

<center><img src='/static/qc-break-rsa_zh/wave-func.png' /></center>
<center>Figure: Real part of wave function at t=0, showing spatial distribution of wave function with position.</center>

### Relationship Between Wave Function Expression and Vector Expression of Quantum States

Some readers might wonder: the state vector form \\(|\psi\rangle = \alpha |S_0\rangle + \beta |S_1\rangle\\) and the wave function form \\(\psi_n(x,t)\\) seem to have no direct connection. Actually, they are two manifestations of the same quantum state in different "coordinate systems."

To describe a quantum state at a certain moment (assume \\(t=0\\)), we must first choose a set of bases.
- The first method uses continuous position basis \\(\{|x\rangle\}_{0<x<L}\\). In this case, the abstract quantum state can be described as \\(\psi(x)=\langle x | \psi \rangle\\), called the wave function, which assigns a complex amplitude to each point \\(x\\).
- The second method uses discrete energy basis \\(\{|n\rangle\}\\). In this case, the abstract quantum state can be described as \\(|\psi\rangle = \sum_n c_n|n\rangle\\), where \\(c_n=\langle n|\psi\rangle\\), which assigns a complex amplitude to each energy eigenstate.

The two coordinates can be transformed into each other:

$$ \psi(x)=\sum_n c_n\sqrt{\frac{2}{L}}\sin(\frac{n\pi x}{L}) $$

These two notations are just different perspectives; they essentially describe the same physical quantity.

<a name="appendix-2"> </a>

## Appendix 2: How Quantum Algorithms Threaten Classical Cryptography

To make it understandable for readers unfamiliar with mathematics or physics, this section will minimize the use of complex mathematical formulas. This may result in some inaccuracies in details but will not affect overall understanding.

### Grover's Algorithm: Accelerating Search Problems

#### Bottleneck of Classical Search

Suppose you have a black-box function \\(f(x)\\) that can determine whether a certain input \\(x\\) is the correct answer:
- \\(f(x) = 1\\): indicates \\(x\\) is the target
- \\(f(x) = 0\\): indicates \\(x\\) is not the target

If \\(x\\) is a 32-bit integer, there are \\(2^{32}\\) possible values. On a classical computer, we can only try \\(f(x)\\) one by one, requiring \\(2^{32}\\) tries in the worst case.

#### How Does Quantum Computing Accelerate Search?

Quantum computers reduce search complexity from \\(O(N)\\) to \\(O(\sqrt{N})\\) through superposition states and interference. The core logic of Grover's algorithm is as follows:

1. Construct superposition state. Quantum computers can make variable x simultaneously represent a superposition state of all possible values, that is, \\(x = 0, 1, 2, \cdots, 2^{32} - 1\\). If these values are substituted into \\(f(x)\\), then \\(f(x)\\)'s result will also be a superposition state of all possible outputs. For some \\(x\\), \\(f(x)\\)'s value is 0; for other \\(x\\), \\(f(x)\\)'s value is 1.

2. Mark the correct answer (Oracle operation). The key to Grover's algorithm is "marking the correct answer." In quantum computing, this marking does not directly tell you the answer but makes the correct answer special at the quantum mechanical level through operations. For example, we do special processing on those \\(x\\) where \\(f(x) = 1\\) (i.e., correct answers): change their "phase." Phase is a property of quantum states that, while invisible itself, can affect the probability distribution when quantum states collapse through subsequent operations. This step is equivalent to putting an "invisible mark" on the correct answer.

3. Amplify the probability of the correct answer through interference. Next, through constructive interference, the amplitude of the correct answer is gradually amplified, and through destructive interference, the amplitude of wrong answers is gradually reduced. This can be imagined as an "amplifier"—each operation makes the presence of the correct answer stronger. Each interference operation further increases the probability of the correct answer. After approximately \\(\sqrt{N}\\) Oracle operations, the probability of the correct answer approaches 1.

4. Measure the correct answer. Finally, by measuring the quantum state, the quantum computer can almost always return the correct answer.

<center><img src='/static/qc-break-rsa_zh/grover.png' /></center>
<center>Figure: Grover's algorithm schematic</center>

#### Cryptographic Application Example: Breaking Hash Functions

Suppose you have a hash function \\(f(x)\\), know a hash value \\(H\\), and want to find some input \\(x\\) satisfying \\(f(x) = H\\). If \\(x\\) is a 4-byte integer (range \\(2^{32}\\)), classical computation requires at most \\(2^{32}\\) tries, while Grover's algorithm only needs approximately \\(2^{16}\\) tries. This acceleration is very useful for password cracking and unordered search.

Similarly, we can also use Grover's algorithm to accelerate breaking symmetric cryptography like AES.

### Shor's Algorithm: Accelerating Integer Factorization

#### Difficulty of Classical Integer Factorization

Integer factorization is a classic problem: given a large composite number \\(N\\), find two integers \\(p\\) and \\(q\\) greater than 1 such that \\(N = p \times q\\). When \\(N\\) is the product of two sufficiently large prime numbers, classical computers need to try a large number of possible values, with time complexity growing exponentially. This is the security foundation of RSA encryption: factoring a 2048-bit integer is an almost impossible task.

#### How Does Quantum Computing Accelerate Integer Factorization?

First, we can transform the integer factorization problem into a "period problem" through number theory knowledge. Shor's algorithm uses quantum Fourier transform to efficiently extract the period, thereby calculating factors. The core logic is as follows:

1. Transform into period problem

Choose a random number \\(a\\), calculate \\(f(x) \equiv a^x \pmod N\\). This calculation generates a periodic sequence, such as:

$$ f(0) = 1, f(1) = 3, f(2) = 9, f(3) = 27, f(4) = 9, f(5) = 27, \cdots $$

The sequence repeats every certain length, and this repetition length is the period \\(r\\). After finding this period, we can quickly obtain a factor of \\(N\\), then recursively factorize other factors of \\(N\\).

2. Quantum Fourier transform extracts period

In classical computation, finding the period requires trying one by one, which is very time-consuming. Quantum computing "simultaneously computes" all possible \\(x\\) through superposition states. By having quantum bits accumulate phases proportional to the period in a series of controlled modular multiplication operations, then using quantum Fourier transform to convert this phase into measurable results, the function's period \\(r\\) can be extracted in polynomial time.

3. Calculate factors

Once the period \\(r\\) is known, factors of \\(N\\) can be quickly factorized through simple mathematical formulas. Specifically, factors of \\(N\\) can be obtained by calculating \\(\text{gcd}(a^{r/2}\pm 1, N)\\).

<center><img src='/static/qc-break-rsa_zh/shor.png' /></center>
<center>Figure: Shor's algorithm breaking RSA schematic</center>

#### Cryptographic Application: RSA Breaking

The security of RSA encryption relies on the difficulty of integer factorization of large numbers. If a classical computer factors a 2048-bit integer, it might take billions of years. Shor's algorithm can complete the factorization in a few hours, posing a direct threat to modern encryption systems.

## References

1. [Beckman, David, et al. "Efficient networks for quantum factoring." Physical Review A 54.2 (1996): 1034.](https://journals.aps.org/pra/abstract/10.1103/PhysRevA.54.1034)
2. [Grover, Lov K. "A fast quantum mechanical algorithm for database search." Proceedings of the twenty-eighth annual ACM symposium on Theory of computing. 1996.](https://dl.acm.org/doi/pdf/10.1145/237814.237866)
3. [Shor, Peter W. "Algorithms for quantum computation: discrete logarithms and factoring." Proceedings 35th annual symposium on foundations of computer science. Ieee, 1994.](https://ieeexplore.ieee.org/document/365700)
4. [Nielsen, Michael A., and Isaac L. Chuang. Quantum computation and quantum information. Cambridge university press, 2010.](https://books.google.com.hk/books?hl=en&lr=&id=-s4DEy7o-a0C&oi=fnd&pg=PR17&dq=Quantum+Computation+and+Quantum+Information.&ots=NJ6Kjjvv-r&sig=lNn_9QhnGo2wkaNXueJqRpNVGKU&redir_esc=y#v=onepage&q=Quantum%20Computation%20and%20Quantum%20Information.&f=false)
5. [Gidney, Craig. "How to factor 2048 bit RSA integers with less than a million noisy qubits." arXiv preprint arXiv:2505.15917 (2025).](https://arxiv.org/pdf/2505.15917)
6. [Gidney, Craig, and Martin Ekerå. "How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits." Quantum 5 (2021): 433.](https://quantum-journal.org/papers/q-2021-04-15-433/)
7. [Krinner, Sebastian, et al. "Engineering cryogenic setups for 100-qubit scale superconducting circuit systems." EPJ Quantum Technology 6.1 (2019): 2.](https://link.springer.com/content/pdf/10.1140/epjqt/s40507-019-0072-0.pdf?pdf=button)
8. [Kjaergaard, Morten, et al. "Superconducting qubits: Current state of play." Annual Review of Condensed Matter Physics 11.1 (2020): 369-395.](https://www.annualreviews.org/content/journals/10.1146/annurev-conmatphys-031119-050605)
9. [Bruzewicz, Colin D., et al. "Trapped-ion quantum computing: Progress and challenges." Applied physics reviews 6.2 (2019).](https://pubs.aip.org/aip/apr/article/6/2/021314/570103)
10. [Browaeys, Antoine, and Thierry Lahaye. "Many-body physics with individually controlled Rydberg atoms." Nature Physics 16.2 (2020): 132-142.](https://www.nature.com/articles/s41567-019-0733-z)
11. [Burkard, Guido, et al. "Semiconductor spin qubits." Reviews of Modern Physics 95.2 (2023): 025003.](https://journals.aps.org/rmp/abstract/10.1103/RevModPhys.95.025003)
12. [Wang, Jianwei, et al. "Integrated photonic quantum technologies." Nature photonics 14.5 (2020): 273-284.](http://nature.com/articles/s41566-019-0532-1)
13. [Castelvecchi, Davide. "IBM releases first-ever 1,000-qubit quantum chip." Nature 624.7991 (2023): 238-238.](https://www.nature.com/articles/d41586-023-03854-1)
14. ["Postquantum Cryptography: The Time to Prepare Is Now!" Gartner Research(2024)](https://www.gartner.com/en/documents/5550295)
15. [Joseph, David, et al. "Transitioning organizations to post-quantum cryptography." Nature 605.7909 (2022): 237-243.](https://www.nature.com/articles/s41586-022-04623-2)
16. [Fowler, Austin G., et al. "Surface codes: Towards practical large-scale quantum computation." Physical Review A—Atomic, Molecular, and Optical Physics 86.3 (2012): 032324.](https://journals.aps.org/pra/abstract/10.1103/PhysRevA.86.032324)
17. ["Quantum error correction below the surface code threshold." Nature 638, no. 8052 (2025): 920-926.](https://www.nature.com/articles/s41586-024-08449-y)
