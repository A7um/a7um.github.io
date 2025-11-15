---
title: Engineering Excellence for Security Researchers
date: 2022-11-10
abstract: This article is intended for security researchers who have developed scripts and personal projects and want to learn more about engineering development.
tags: [software-engineering]
---


This article is intended for security researchers who have developed scripts and personal projects and want to learn more about engineering development.

## About Engineering Development

Compared to personal development by security researchers, the main characteristics of engineering development are:

1. **Requires high-quality collaboration methods.** Generally, engineering development involves multiple developers (>3), and collaboration efficiency directly impacts the efficiency and quality of engineering development.
2. **Larger project scale.** Engineering development target projects typically have larger code bases and higher complexity.
3. **Iterative high-quality delivery goals.** Engineering development delivery targets usually require continuous iteration, and each iteration typically has high-quality requirements. This demands high standards for process standardization, code correctness, and maintainability.

This requires engineering development to have:

1. An efficient collaboration method, such as clear coding standards, good developer documentation, and standardized code submission processes.
2. An appropriate software architecture and reasonable code structure, so that large amounts of code can remain organized and non-interfering.
3. Clear development, testing, and delivery iteration processes (DevOps), and regular repayment of technical debt. For example, applying agile development thinking. When necessary, also consider introducing tools such as CI/CD. Additionally, we need to choose appropriate languages based on project characteristics.

Based on the characteristics and needs of engineering development described above, the following article will detail four aspects: **collaboration**, **software architecture and code structure**, **delivery and iteration processes**, and **programming language selection**.



## Collaboration

To achieve high-quality collaboration, we first need a method for requirements management and task allocation to clarify requirements and development responsibilities. During the development process, we need clear coding standards to ensure code readability within the team. When necessary, we also need to build developer documentation to facilitate communication among developers. We also need to clarify the code submission process to reduce code merge conflicts and improve code traceability.

### Requirements Management and Task Allocation

When a project has multiple developers, we may need to clarify each specific development requirement and responsible person. One approach is to clarify requirements through issues and assign issues to specific responsible persons for development, so everyone in the team knows what they are doing.



### Coding Standards

The main purpose of coding standards is to improve code readability within the development team and enhance code maintainability. Although specific coding standards vary from person to person, there are still some universal coding standards that can be listed:

1. Reasonable naming.
2. Functions and classes follow the single abstraction principle.
3. Mark todos where improvements are needed.
4. Write Type Hints for all definitions in dynamically typed languages to facilitate type checking.

```python
def some_interface(arg1: Type1, arg2: Type2) -> Type3:
    some implementation
```

5. Add comments describing interface functionality and parameter details in interface code.
6. Write comments explaining functionality in hard-to-understand code.

```python
def tricky_function():
     # this code do xxxx things to achieve xxx goal
     some tricky code
```

7. Properly print logs and throw exceptions.

**Recommended Reading:**  
*State-of-the-Art Shitcode Principles (highly recommended)*



### Developer Documentation

Writing developer documentation is meant to reduce developers' workload.

This statement may contradict everyone's inherent impression of documentation. Most people believe that writing documentation is a time-consuming and tedious task. Yes, if a project's development team has fewer than 3 people, most development-related content can be aligned in meetings, and the benefit of writing documentation is indeed not high.

But let's imagine a scenario where the development team has 5 people, each responsible for a module and providing interfaces to others. If developers don't write documentation at the beginning, they may be asked questions about their modules by other developers at any time. When a question is asked multiple times, they may tend to write this question and other potentially asked questions into documentation. Continuing to imagine, one day, a new developer joins the development team. This new developer needs to ask old developers a lot of questions to get started with development. To avoid this situation happening again, developers and project leaders will also tend to build good documentation.

This is how the need for writing developer documentation arises. Writing documentation is not random, nor is it writing for the sake of writing, but rather placing things that need to be synchronized with others in the documentation like a bulletin board to reduce the frequency of inquiries, thereby enabling efficient collaborative development among developers. If this situation doesn't exist in the project development process, documentation is not necessary.

This is why I said at the beginning of this section that writing documentation is to reduce developers' workload.

**Recommended Material:**  
*Book, The Pragmatic Programmer*



### Code Submission Process (Git Workflow)

As a version management tool, Git has become deeply ingrained. The so-called Git Flow is actually a specification for how to submit code using Git. An appropriate Git Flow can effectively reduce code merge conflicts and improve code traceability in multi-person collaboration scenarios.

**Recommended Reading:**  
*Gitflow Workflow*



## Software Architecture and Code Structure

An appropriate software architecture and reasonable code structure will greatly increase code quality and iterability. Next, we will explain how to choose an appropriate software architecture and reasonable code structure.

### Software Architecture

First, software architecture here does not discuss how to define functions and classes, which belong to the category of code structure. Software architecture is a macro concept. Some positive examples are MVC (a monolithic layered architecture) and microservices (a distributed domain-isolated architecture). Some negative examples are factory pattern and producer-consumer pattern.

An appropriate software architecture can effectively organize developers, reduce coupling between developers from different teams, and enhance cohesion among developers in the same team. If the development team is organized by technical direction such as "frontend," "backend," "database," you may be more suitable for layered architecture, which is technology-oriented. If the development team is organized by domains such as "reverse engineering," "data analysis," "data collection," then service architecture based on domain isolation is more appropriate.

> "Software architecture is about compromise."

I very much agree with this statement. There is no best architecture, only the most suitable architecture.
If you choose a monolithic architecture (such as layered architecture, plugin architecture), you may need to compromise on architectural characteristics such as availability, scalability, and recoverability. If you choose a service-based distributed architecture, you may need to compromise on consistency, efficiency, and testability.

Therefore, before choosing your architecture, you first need to clarify what requirements your project has for architecture (such as availability, scalability, etc.), and clarify whether the project is isolated based on technical direction or domain. After clarifying these things, then choose the most suitable architecture.

**Recommended Material:**  
*Book, Fundamentals of Software Architecture*



### Code Structure

The goal of designing code structure is to achieve modularization through abstraction (i.e., high cohesion, low coupling).

However, abstraction has a cost, and the complexity of abstracted code will inevitably increase. For example, suppose the business logic layer of a program needs to perform CRUD operations on a database. The simplest implementation is to directly use the relevant API for CRUD operations. But if we want to support multiple different databases, we may need to abstract the database interface and implement a specialized factory or apply dependency injection to create specific database access instances. Obviously, this reduces the coupling between database access and business code, but it also increases complexity.

A classic anti-pattern of code structure design is "premature abstraction," which means racking your brains to think of the "most suitable" code structure in the early stages of project development. "Premature abstraction" greatly increases the cost of project startup. Moreover, project requirements are usually dynamic, and these carefully considered "premature abstractions" are most likely inappropriate.

The best practice for code structure design is to find a balance between code abstraction and code complexity, roughly achieving the goal of modularization while not making the code particularly complex. At the same time, it should be able to quickly modify the code architecture when requirements and design change.

Remember, requirements are continuously changing, code structure is continuously changing, and "premature abstraction" is meaningless.

**Recommended Material:**  
*Book, Fundamentals of Software Architecture*



## Iteration and Delivery

To ensure high-quality iteration and delivery as much as possible, we may need a process called DevOps to manage the application lifecycle. In situations where requirements are unclear or frequently change, we may also need to apply agile development thinking. In addition, when the project is large and the system is complex, we can also make project integration and delivery smoother by deploying CI/CD.

> ⚠️ Warning: All content in this section should be adopted only when necessary based on actual circumstances. If a project's requirements are relatively fixed, applying agile development is meaningless. If the project is small, applying CI/CD is also a huge waste.



### DevOps

I believe the term DevOps is both familiar and unfamiliar to many security researchers. Familiar may be because this term will most likely be encountered in security research, as it is a very important application scenario for security technology (DevSecOps). Unfamiliar is probably because doing security research rarely requires participation in DevOps, so there is a lack of practical experience in this area.

So what is it exactly? I think its literal meaning is already very vivid: a project iteration process that closely combines development and operations.

It clarifies the entire process of project requirements collection, development, testing, delivery, operations, and feedback. This greatly improves the delivery quality and maintainability of the project.

Imagine a scenario where a team collaboratively develops a binary analysis project. Binary analysis requires significant investment. Before development, we must undoubtedly understand why we need to develop this project and what problems it needs to solve. After clarifying these requirements, we can begin architecture design and development.

After code development is completed, we must also clarify what tests the code must pass before merging (such as code style testing, static bug scanning, unit testing, code review, integration testing, etc.). If these tests are not clarified, code quality cannot be guaranteed, and code can easily become a mess and difficult to maintain.

In the delivery and operations cycle, we need log aggregation and runtime environment monitoring to maintain observability of the software and discover bugs in a timely manner (for example, errors are printed in logs, exceptions are discovered, and there's also the issue of how to make a bug reproducible). We also need to continuously collect user feedback (although sometimes the users are ourselves).

Finally, based on the collected information and user feedback, we clarify the requirements for the next iteration cycle, reflect on technical debt that needs to be repaid, and conduct the next round of iteration and improvement.

Through the above example, we can understand that DevOps is not just a slogan, but a process that can truly improve software quality and maintainability.

**Recommended Material:**  
*What is DevOps*



### Agile Development

Agile development is one of the most commonly used software iteration philosophies today. Mentioning agile development here is mainly to emphasize that agile development is not rapid development. The main idea of agile development is to shorten the DevOps cycle and reduce the changes made in each cycle to adapt to rapid changes and iterations in requirements.

Many people simply understand agile development as rapid development and think that the code quality produced by agile development is poor. This is actually a misunderstanding of agile development.

In the agile development process, developers still need to go through each process of DevOps, and development is just one step in this process. Therefore, agile development can actually improve code quality because its iteration cycle is shorter, allowing for more timely review, reflection, and repayment of technical debt.

**Recommended Material:**  
*What is Agile Development*



### CI/CD

Continuous Integration/Continuous Delivery (CI/CD) shortens the software integration and delivery cycle, and can even eventually shorten the integration and delivery cycle to the commit level. The main benefit of doing this is to make integration and delivery smoother, effectively avoiding bug outbreaks on software integration and delivery days.

Integration and delivery itself has costs. To achieve continuous integration and delivery, the cost of integration and delivery must be reduced. Therefore, CI/CD is usually associated with automation, which is why CI/CD typically manifests in projects as something like:

> An automated pipeline of "static code checking -> build -> unit testing -> integration -> integration testing."



## Language Selection

Languages are neither good nor bad, only whether they are suitable. I personally recommend three languages: **Python, Kotlin, and Rust**. These three languages can basically handle most development needs in security research.

Overall:

- Python is a versatile language, suitable for almost all scenarios where execution efficiency is not sensitive and business logic is not particularly complex;
- Kotlin is a modern version of Java, inheriting Java's ecosystem, suitable for developing complex business logic;
- Rust has efficiency comparable to C++ and powerful various checkers, suitable for developing performance-sensitive and bug-sensitive projects (such as fuzzing).

Next, I will introduce the advantages and disadvantages of each language as I understand them, and explain the scenarios they are suitable for based on these pros and cons.



### Python

**Advantages:**

1. Mature ecosystem with rich libraries, enabling quick completion of various development needs.
2. Simple syntax, easy to get started, high development efficiency.
3. Interpreted execution, no compilation needed, facilitating quick code modification and dynamic debugging.

**Disadvantages:**

1. Weak type system, difficult to build relatively useful type checking capabilities. When writing relatively complex projects, the experience of statically finding bugs is poor.
2. Due to interpreted execution plus the impact of GIL and other factors, Python's execution efficiency is low.
3. Package management system is currently relatively primitive.

Overall, Python is quite versatile and can be used in most scenarios, especially suitable for scenarios with diverse requirements and high development efficiency demands. However, it is recommended to mark type hints during development to facilitate using type checking to eliminate bugs. However, due to Python's dynamic typing, weak type system, and relatively free syntax, developing maintainable high-complexity projects is more difficult.



### Kotlin

**Advantages:**

1. Compatible with Java, can directly use Java's ecosystem, can be mixed with Java, supports one-click conversion of Java code to Kotlin.
2. A relatively modern language with support for Null Free, functional programming, etc. Has rich syntactic sugar (such as property access, etc.), excellent coding experience.
3. Has a relatively mature package management system.
4. Type-safe, can use type checking at compile time to eliminate most bugs.

**Disadvantages:**

1. Compiled language, every code modification requires recompilation, which has some impact on dynamic debugging efficiency.
2. Poor support from third-party IDEs and editors, development heavily depends on the official IDE IntelliJ. IntelliJ has many analyses to run and is very resource-intensive (sometimes even M1 Macs run slowly).

Since Kotlin can directly use Java's ecosystem and is a relatively modern language, it is a good alternative to Java, basically solving Java's lack of modern syntactic sugar and various Null Pointer Exception pain points. Kotlin is very suitable for scenarios where Java was previously suitable, such as developing complex business logic.



### Rust

**Advantages:**

1. Native, execution efficiency comparable to C++.
2. The compiler's Type Check and Borrow Check eliminate most code bugs at compile time, with only a very few bugs left to trigger at runtime.
3. A relatively modern language that has basically eliminated some syntax problems of C++/C, with support for Null Free, functional programming, etc.
4. Has a relatively mature package management system.

**Disadvantages:**

1. Steep learning curve, slow to get started, and relatively few people know it.
2. The language is relatively young, and the ecosystem is not yet complete.
3. Borrow check and other checking make some code impossible to write, in which case you can only write using the unsafe backdoor.

Rust is a relatively young language that has successfully shed the historical baggage of C++/C. Therefore, it can be used as a replacement for C++ to develop code with high efficiency requirements, such as Fuzzers.
