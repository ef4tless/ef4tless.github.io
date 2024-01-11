---
title: VMware ESXI 历史漏洞复现
date: 2023-01-09 15:11:40 +0800
categories: 
tags: 
permalink: /posts/id=78/
pin: false
published:
---
参考文章
https://github.com/knownsec/KCon/blob/master/2023/vSphere%20%E6%94%BB%E9%98%B2%E6%8A%80%E6%B3%95%E5%88%86%E4%BA%AB.pdf

SLP 是一个网络服务发现协议，它允许计算机和其他设备在网络上查找服务
一些信息如下：
```
slpd: SLP 服务进程
监听tcp:427端口
认证前可访问
ESXi 5.5后以root权限运行
默认启用 (ESXi 7.0 U2c前版本)
单线程进程
```

ps -Z



找sldp的二进制文件
```shell
netstat -pantu | grep 427
```


CVE-2019-5544(堆溢出)
CVE-2020-3992(UAF)  ESXi70U1a-17119627完整修复
CVE-2021-21974(堆溢出) ESXi-7.0U1c-17325551完整修复
CVE-2022-31699(堆溢出)

CVE-2020-3992、CVE-2021-21974修复后, SLP服务只能本地访问( 127.0.0.1(ipv4) or ::1(ipv6)).
CVE-2022-31699 无法用于RCE, 可用于沙箱逃逸（ESXi 7.0u2前版本, 尤其是ESXi 6.7）.

7.0u2后, SLP服务在沙箱中运行.
7.0u2c后, SLP服务默认禁用.


add-symbol-file可以使用esxcfg-info如下命令获取所需的模块基地址和路径信息：











## 2022 qwb final pbc






## 参考文章

[我针对 (CVE-2021–21974) VMware ESXi OpenSLP 堆溢出漏洞的RCE PoC 演练](https://straightblast.medium.com/my-poc-walkthrough-for-cve-2021-21974-a266bcad14b9)
[CVE-2021-21974.py](https://github.com/straightblast/My-PoC-Exploits/blob/master/CVE-2021-21974.py)












