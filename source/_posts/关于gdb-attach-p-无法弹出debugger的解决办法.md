---
title: 关于gdb.attach(p)无法弹出debugger的解决办法
date: 2020-01-01 14:14:53
tags: 笔记
---

写一小段exp试验<!--more-->  
```Python
#coding=utf-8
from pwn import *
#context.log_level = "debug"
context.terminal = ['terminator','-x','sh','-c']
sh = process("./pwn")
elf = ELF('./pwn')
sh.send('N0vice')
gdb.attach(sh)
sh.interactive()
```
![](gdb_1.png)
一直在Waiting for debugger  
我后来看了swing师傅的博客有一个解决办法，swing师傅的博客讲的很详细，我就不献丑了，直接贴上swing师傅的链接  
[解决升级pwntools gdb.attach不能弹起gdb](https://bestwing.me/after-upgrade-gdb-wont-attach-to-process.html)  
恍然大悟，我一直是用的root用户写exp跑exp，所以一直出不来gdb，这次我先按照师傅说的改一下配置文件，然后再切换回普通用户去跑一下exp  
![](gdb_2.png)  
困扰已久的问题终于解决了！