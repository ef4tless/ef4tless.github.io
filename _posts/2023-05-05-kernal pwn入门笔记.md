---
title: kernal pwn 入门笔记
date: 2023-05-05 19:54:59 +0800
categories: [漏洞利用总结]
tags: [pwn, ctf]
permalink: /posts/id=64/
pin: false
published:
---



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





