---
layout: post
title: CTF中的玄学问题汇总帖
categories: CTF
description: 记录CTF中的一些奇怪的问题
keywords: CTF, 玄学问题
---

# CTF中的玄学问题汇总帖

在CTF中乃至coding的过程中，由于对系统的运作机制、库函数的实现等内容不够了解，编写代码时常常会遇到一些的以代码的行为与代码所表达的逻辑不相符的情况。这些情况在比赛时尤其是AD模式的比赛时一旦遇到都会严重打乱比赛的节奏，导致无法发挥出队伍原有的水平。所以我在此帖中整理了我在比赛中遇到的一些代码行为与代码逻辑不相符的情况，分析其原因并给出解决方案，以免以后再次遇到这些情况时不知所措，本文根据我个人比赛经历的增加会持续增长。

## 输入输出相关的问题

输入输出是CTF Pwnable题目的家常便饭，所以这一类问题在CTF PWN题也比较普遍。

### Linux/Unix Socket缓冲区导致的输入输出问题

#### 问题描述

比如当目标服务接受数据的代码为以下代码时

```
read(0,buf1,20);
read(0,buf2,20);
```

如果攻击脚本中使用以下代码进行交互

```
io = remote(ipaddress,port)
io.sendline("1")
io.sendline("2")
```

根据代码的逻辑，字符串"1\n"将会被读到buf1中，字符串"2\n"将会被读到buf2中，但是实际上以上代码的实际行为是不确定的，代码行为可能是正常的，也可能存在字符串"1\n2\n"会被读到buf1,而buf2无法读到任何字符的异常情况

#### 问题解析

由于pwntools的流量是TCP流量，对于TCP而言，数据的发送和接收是以流的形式进行的，为了效率，类Unix操作系统在内核中实现了一套缓冲区机制，发送和接收的数据都会被缓冲。

所以，当攻击脚本先后执行sendline("1")和sendline("2")，字符串"1\n2\n"可能会被同时缓冲到发送缓冲区中，当发送缓冲区timeout的时候，字符串"1\n2\n"会作为一个TCP包被发送到目标主机并缓存入接收缓冲区，目标服务的read(0,buf1,20)则会从接收缓冲区中取不超过20个字符，从而导致整个字符串"1\n2\n"都被取出来。

#### 解决方案
当目标服务使用read等无终止字符进行读入时，攻击脚本在两次sendline之间要使用sleep等函数进行间隔，使得两次发送的数据被封装在两个TCP的包中。或者通过padding填满read的长度(不建议）

```
io = remote(ipaddress,port)
io.sendline("1")
time.sleep(0.1)
io.sendline("2")
```

### glibc缓冲区导致的输入输出问题
#### 问题描述
当目标服务以以下代码接收数据

```
scanf("%3s",buf1);
read(0,buf2,20);
```

如果攻击脚本使用

```
io = remote(ipaddress,port)
io.sendline("see");
io.sendline("you");
```

根据代码逻辑，执行结果应该是**buf1=="see" && buf2=="you"**,但是以上代码的执行结果却为**buf1=="see" && buf2==""**，也就是说，read没有读入任何数据。

#### 问题分析
C语言中常用输入输出函数分以下两类

* 系统调用(如read、write)
* glibc的输入输出函数(如puts、scanf)

系统调用如read、write是直接从fd中直接获取数据，在此我们将场景假定在CTF题目中，stdin、stdout会被重定向到网络，那read、write函数将直接从网络缓冲区取数据。

而glibc中的函数却需要走一套glibc的缓冲机制，当执行scanf函数时，scanf会尝试从glibc的输入缓冲区中读入数据，如果输入缓冲区为空，glibc会将Socket的接收缓冲区中的一定字节的数据缓冲到glibc的输入缓冲区，之后scanf会接着从glibc的输入缓冲区读入数据。

所以，执行**scanf("%3s",buf1);**的时候,字符串see和字符串you都会被缓冲到glibc的缓冲区，从而导致read函数无法读到任何内容。

#### 解决方案

攻击脚本在两次sendline之间要使用sleep等函数进行间隔，使得两次发送的数据被封装在两个TCP的包中。或者通过padding填满缓冲区(不建议）

```
io = remote(ipaddress,port)
io.sendline("1")
time.sleep(0.1)
io.sendline("2")
```





