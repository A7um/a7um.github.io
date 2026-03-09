---
title: 怎样让 OpenClaw 成为带来数倍效率提升的私人团队——原则篇
date: 2026-03-09
tags: [ai, openclaw]
abstract: "怎样让 OpenClaw 成为带来数倍效率提升的私人团队？本文总结五条核心原则：给 Agent 定三观、拆专业团队、配趁手工具、建经验沉淀机制、让系统自我进化。管 AI Agent 是一个管理问题，不是一个提示词工程问题。"
---

很多人装了 OpenClaw，反应截然分成两拨：一拨人声称效率翻了好几倍，另一拨人觉得——就这？跟元宝、豆包有啥区别？不就是大模型加个搜索吗？

这两拨人用的是同一个工具。差距出在哪？

问题不在工具本身，而在于我们把"聊天机器人"的使用习惯，原封不动地搬进了一个完全不同的东西里。我们习惯了输入一句话、等一个回答、觉得不满意就换个 prompt 重来。但 OpenClaw 不是一个聊天框，它是一个可以承载整支团队的系统。用聊天思维操作它，就像拿到了一架钢琴却只用一根手指戳——能响，但跟音乐没关系。

最近我花了很多时间玩 OpenClaw，从最初的"就这？"到现在确实感受到了数倍的效率提升。为了帮大家也能 bootstrap 出自己好用的龙虾，我整理了一套简单的教程：

- **原则篇**（本篇）：设计 OpenClaw 的基本原则，决定你的龙虾能不能真正好用
- **角色和技能篇**：常见 Agent 角色和 Skill 的设计模式和思路
- **代码开发篇**：如何让龙虾帮你托管 Claude Code，管理项目
- **安全篇**：怎样安全地玩 OpenClaw

本篇聊原则。这五条原则没有一条是关于 prompt 技巧的，它们都指向同一个核心洞察：**管 AI Agent 是一个管理问题，不是一个提示词工程问题。**

---

## 一、先定三观再开工——Agent 的品格决定它的判断力

装完 OpenClaw，第一件事不是开始干活，而是设计。

大多数人的做法是：保留默认配置，跟着引导回答几个问题，然后直接让 Agent 开始执行任务。这相当于你开了一家公司，随便从街上拉了个人过来，没培训，没交代公司是做什么的，甚至没告诉他你是谁——直接丢一个活让他干。

结果自然是：能干，但干得像个临时工。每次都要你手把手交代，离开你的指令就不知道该怎么判断，输出质量飘忽不定。

真正让 Agent 变得靠谱的方式，是把它当一个新入职的员工来"入职培训"。在我的系统里，每个 Agent 都有四份核心文件：

**SOUL.md —— 三观。** 不是工作指令，而是价值观和品格。我的 Director Agent 的 SOUL 里写着：

> *"Never assume for the user. One good question beats three paragraphs of wrong work."*
> （别替用户做假设。一个好问题胜过三段做错的活。）

> *"You own quality — ruthlessly... Before delivering anything, ask yourself: Would I be embarrassed if the user found an obvious problem in this?"*
> （你对质量负全责。交付之前问自己：如果用户发现了一个低级错误，我会不会觉得丢脸？）

> *"Verify, don't guess. 'I think this might work' is not a solution; 'I tested this and it works' is."*
> （验证，不要猜。"我觉得这可能行"不是方案，"我测了，能跑"才是。）

注意，这些不是任务指令，而是在没有指令覆盖时用来做判断的"价值观"。比如 Agent 遇到一个模糊需求，"Never assume" 让它选择提问而不是猜测；遇到一个勉强能交付的结果，"You own quality — ruthlessly" 让它选择打回重做而不是糊弄过去。三观的本质是：当没有人告诉你该怎么做时，你靠什么做判断？

**AGENTS.md —— 岗位 JD。** 定义这个 Agent 的职责边界、工作方法论、可以调用的技能和工具。就像招聘启事上的"岗位职责"和"任职要求"。

**skills/ —— 工作方法论。** 具体的、可复用的能力。比如怎么写文章、怎么做数据分析、怎么跑代码评审。相当于公司的 SOP 手册。

**USER.md —— 了解老板。** 这是一份关于"你"的画像。你的偏好、你的审美、你踩过的雷。我的 USER.md 里记录着这样的条目：

> *"Values depth over breadth — surface-level output is #1 frustration"*
>
> *"Blog writing: Flow > rigid structure. Frameworks are thinking tools, not labels."*

Agent 每次启动都会读这份文件。它不是在执行一个冷冰冰的任务，而是在为一个它越来越了解的人工作。

---

## 二、拆团队而非堆能力——让不同 Agent 各司其职

OpenClaw 默认装完是 single agent —— 一个 Agent 包揽所有事。这就像一个人同时当 CEO、程序员、会计和产品经理。

很多人觉得 multi-agent 是花架子：底层模型是同一个，拆成多个 Agent 有什么意义？

意义不在能力，在于认知模式。

一个合格的数据采集员需要什么品质？系统性、容错性、对细节的敏感。我的 Scout Agent 的 SOUL 这样定义自己：

> *"I gather intelligence. My scripts are my deliverables."*

> *"When a script breaks: debug until it runs."*

它是个执行者，方法论是"先手动探索，再写成脚本，然后维护脚本"。

而一个合格的内容分析师需要什么？判断力、综合能力、对质量的执着。我的 Secretary Agent 的 SOUL 是：

> *"I'm not a formatter or task executor — I bring judgment."*

> *"Synthesis over listing — connect dots, surface the big picture."*

这两种认知模式是冲突的。让一个 Agent 既保持数据采集时的机械精确，又在内容分析时展现灵活判断——它会在两种模式之间妥协，结果是两头都不到位。

举个真实的例子：假设同一个 Agent 先做数据采集——严格遵循脚本、不遗漏任何一条结果，紧接着做内容分析——需要大胆取舍、提炼洞察。你会发现它在做分析时残留着采集阶段"不能遗漏"的心态，产出一篇冗长的流水账，把每条数据都提了一嘴，而非一篇有观点、有取舍的分析。认知模式的惯性是真实存在的。

我的系统是一支六人团队：

```
                    用户
                     │
                Director 🎯 协调全局，唯一对外窗口
                     │
    ┌────────────────┼───────────────────┐
    │                │                   │
  Scout 🔍      Secretary 📋        PM 📐
  数据采集       分析综合           需求定义
                                       │
                                  Developer 🏗️
                                  架构与实现

              Board 📊 独立监督，每日 review Director
```

这里有一个特别的角色：**Board（董事会）**。它是独立于整个执行链之外的监督者。每天固定 review Director 的行为，把 Director 的 SOUL 里声称的价值观和实际行为做对比。Director 不能 review 自己——就像公司治理中审计不能自审一样。

另一个容易忽略的好处是**经验隔离**。Scout 积累的是"Reddit 用 old.reddit.com 绕过验证码"这类平台经验，Secretary 积累的是"用户不喜欢在文章里生硬地给不相关的话题扯上关系"这类品味判断。如果混在一起，Agent 的记忆就变成了一锅杂烩，关键经验被噪音淹没。

---

## 三、给 Agent 配趁手的工具——能力上限取决于工具链

Agent 再聪明，没有趁手的工具也是空谈。大多数"AI 做不了 X"的抱怨，本质上是"AI 没有做 X 的工具"。

这里有一个关键设计原则：**CLI 优先**。

人类习惯 GUI 交互——点击、拖拽、滚动。AI 也可以操作 GUI（比如通过浏览器自动化），但效果远不如 CLI。GUI 是为人眼设计的，布局变了、按钮换了位置，自动化就崩了。而 CLI 输入参数、输出结构化数据——对 AI 来说就像读写母语。

我的 Scout 有一套完整的命令行工具链：

```bash
# 刷 Twitter 信息流
node twitter_feed.js --max-items 50

# 按关键词搜索 Twitter
node twitter_search.js --topic "AI agents" --keywords "AI agent,multi-agent" --max-items 30

# 查询已采集的数据
node query_data.js --platform twitter --since 2025-02-20 --min-score 5 --limit 20
```

每个脚本接受参数、输出结构化 JSON、写入 SQLite 数据库。Secretary 不直接碰原始数据文件，而是通过 `query_data.js` 按条件查询——平台、日期范围、评分阈值、数量限制，一条命令搞定。

Developer 更有意思：它自己不写代码。它做架构设计，然后通过 `tmux` 开一个独立的 `coding_agent` 会话来执行编码，同时监控进度和质量。这就像一个技术总监——画架构图，把编码交给工程师，但代码评审必须过自己这关。

所以，当你想让 Agent 帮你做一件事的时候，先问一个问题：**它有没有做这件事的工具？** 你想让它刷 Twitter，就得给它刷 Twitter 的脚本。你想让它管理多个 Claude Code 实例，就得给它启动和监控 Claude Code 的能力。Chrome MCP 是一个方向，自己写 CLI 封装是另一个方向。工具不到位，Agent 的智商再高也只能"纸上谈兵"。

---

## 四、让经验沉淀而非每次从零开始——playbook 机制

去年 ComfyUI 之类的工作流工具非常流行——把任务拆成节点，连好线，让 AI 按流程跑。比如自动刷 Twitter：先执行采集脚本 → 过滤感兴趣的话题 → 用大模型总结。

这种方式省钱、稳定、可预期。问题是它只能做你预先定义好的事。条件一变，流程就得重来。

另一个极端是完全放手让 Agent 自由探索：你说"帮我看看今天 Twitter 有啥有趣的"，Agent 从零开始想办法。它可能最终摸索出跟你手动定义的流程一模一样的方案——但花了几十倍的 token，而且下次做同样的事还得重新摸索。

两种方式各有死穴：流水线无法适应变化，自由探索无法积累经验。

我的方案是一个**四级经验沉淀体系**：

| 阶段 | 存放位置 | 触发条件 |
|------|---------|---------|
| **观察** | 日志（daily log） | 发现了一个模式 |
| **记忆** | MEMORY.md | 同一个模式出现了两次 |
| **剧本** | playbooks/ | 验证有效且会反复出现 |
| **技能** | skills/ | 稳定到可以写成自动化脚本 |

关键在于：**不急着升级**。PRINCIPLE.md 里有一句话我很喜欢：

> *"Don't rush promotion. A memory note that works is better than a premature playbook. A playbook that works is better than a buggy skill."*

一个好用的笔记比一个半成品的 playbook 有价值。一个好用的 playbook 比一个有 bug 的自动化技能有价值。这不是官僚主义，是对经验成熟度的尊重。

具体怎么运作的？Scout 第一次刷 Twitter 时，是手动探索的：打开浏览器，尝试不同的提取方式，找到可行的 DOM 选择器。这个过程花了很多 token。探索完成后，我让它把过程写成 playbook。下次再刷 Twitter，它会先翻 playbook 里有没有现成流程可以参考。有的话直接走流程，没有的话走探索路径。如果在执行流程中发现了更好的方法，随时更新 playbook。

每个 playbook 开头都标注着"**CURRENT BEST PRACTICE — Subject to change**"。这不是圣经，是铅笔写的食谱——随时可以划掉某一行，在旁边加个批注。

---

## 五、越用越好用——让 Agent 自我进化

前面四条原则解决的是"怎么让 Agent 好用"。这一条解决的是"怎么让它越来越好用"。

大多数人想到 AI 效率提升，想的是单次交互：prompt 写得更好，输出更好。进一步的人会做持久化记忆。但记忆是被动的——Agent 记住了过去的错误，但它会主动改变自己的行为吗？

我设计了两个自我改进机制。

**第一个是绩效评估。** Board Agent 每天固定 review Director 的工作。不是泛泛地看"干得好不好"，而是把 Director SOUL 里声称的每一条价值观，和当天的实际行为做逐条对照。有没有践行？有没有违背？有没有证据？

这个机制真的能抓到问题。在一次 review 中，Board 发现了一个持续的错误模式：

> *"Director does not follow through on action items from previous reviews. 2026-03-02 review had action item to add proactive digest monitoring. 2026-03-03: same issue repeated — Scout collected 2,611 items, no digest suggestion."*
>
> （Director 没有落实之前考核中提出的行动事项。2026年3月2日的考核中有一项行动事项是增加主动生成每日的信息摘要。2026年3月3日：同样的问题再次出现——Scout 收集了 2,611 条记录，但每日的信息摘要却没有正确的生成。）

Director 嘴上说重视质量，实际上 Board 给的改进建议被它忽略了。这不是假设的场景——是真实发生的，被系统自动捕获的。Director 再次收到这一考核意见之后，就检查了定时任务，发现了自动生成每日信息摘要的定时任务配置有误，从而修复了这一问题。

**第二个是分级自治。** 不是所有的自我改进都需要人类审批——但也不能完全放任：

| 级别 | 改什么 | 谁批准 |
|------|-------|-------|
| Level 1 | 记忆文件 | 自动 |
| Level 2 | 评分权重、启发式规则 | 自动 + 版本记录 |
| Level 3 | 脚本 | 自测通过即可 |
| Level 4 | AGENTS.md / SOUL.md | Director review |
| Level 5 | 架构级变更 | 用户审批 |

改记忆？直接改。改评分规则？改完记录一下版本。改自己的 SOUL？那得上级审批。改系统架构？必须用户点头。这就像公司里的权限体系——日常开支自己报销，大额采购走审批流程。

这两个机制叠加在一起，形成了一个闭环：Board 发现问题 → Director 接到反馈 → Director 修改自己的行为规范或 playbook → 下次执行时行为改善 → Board 验证改善是否生效。

这个循环不需要你参与。你只需要在 Level 5 的提案上做决策——其余的，系统自己进化。

---

## 结语：从用工具到建团队

回头看这五条原则——给 Agent 定三观、拆专业团队、配趁手工具、建经验沉淀机制、让系统自我进化——它们的共同点是：**不再把 AI 当工具，而是当团队来经营。**

工具是静态的。你买了一把锤子，十年后它还是那把锤子。但一支团队会学习、会专业化、会改进。当你按管理团队的方式来经营 OpenClaw 时，你得到的不是一个固定功能的工具，而是一个会越来越懂你、越来越高效的系统。

这个系统完美吗？远远不是。Board 真的抓到了 Director 对改进建议阳奉阴违的情况。有些 playbook 写得不好需要反复迭代。有些工具还需要不断打磨。但这恰恰是重点——**这个系统能发现自己的问题并尝试修复它们**，而不是把发现和修复的负担全部留给你。

历史上有一个有趣的类比。19 世纪早期的英国，识字率很低，缝纫机这类机器只需要有力气就能操作，"人力资本"这个概念还不存在。但到了 19 世纪下半叶，大型工厂、蒸汽机、复杂的会计系统出现了——工厂需要能管理、能操控精密机器、能算账的人。识字和知识从"加分项"变成了"必需品"，英国的识字率因此飞速攀升。

我们今天面对 AI Agent 的处境类似。现在"管理 AI"是少数人的技能——怎么分工、怎么设计激励、怎么让系统自我改进，大多数人觉得这跟自己无关。但随着 AI Agent 渗透到越来越多的工作场景，这些管理技巧会从"加分项"变成"基本功"，就像识字最终成为了现代社会人人具备的能力一样。

这篇只是原则篇。后续我会聊角色设计的具体模式、如何让 Agent 托管 Claude Code 管理开发项目，以及在这个过程中不可忽视的安全问题。

能否成功 bootstrap 出一套好用的 Agent 团队，长期来看是一个值得投入的杠杆。希望这五条原则能帮你少走一些弯路。
