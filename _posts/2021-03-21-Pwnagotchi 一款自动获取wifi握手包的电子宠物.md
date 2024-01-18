---
title: Pwnagotchi 一款自动获取wifi握手包的电子宠物
date: 2021-07-31 22:54:59 +0800
categories:
  - IOT
tags:
  - pwn
permalink: /posts/id=2/
pin: false
---
> 前段时间对树莓派突然感兴趣，于是就购买了一个树莓派zero wh ，在搜索配置教程的时候偶然看到了一个名叫pwnagotchi的项目，是一个电子宠物型的人工智能项目，以wifi握手包为食，会感到开心和悲伤，同时还会不断学习，更换捕获握手包的方式，感觉很有趣，于是准备上手一试。

## 准备材料

硬件：树莓派zero wh（带wifi和蓝牙，焊接排针），一块2.13英寸的微雪水墨屏V2，16GB及以上的TF卡，一个高速的读卡器，micro-usb线*2，5V2A的插头（或者充电宝，蓄电池电源等）

软件：VScode等（后文会提到）

## 开始安装

+ 1.先下载pwnagotchi的系统镜像，因为官方版本没有中文，这里我推荐极客之眼论坛的[中文整合完美时钟版](https://www.geekeyes.cn/forum.php?mod=viewthread&tid=1783)，下载img镜像，然后用[etcher](https://www.balena.io/etcher/)烧录进TF卡里（建议以管理员权限运行），烧录完成以后进入boot分区，用vscode打开`中文新装引导配置config.toml`，按文件内的中文说明设置你的宠物，修改完成后把文件名中的中文删掉就配置完成了。

+ 2.然后将TF卡插入树莓派，将水墨屏和树莓派安装在一起（安装的时候注意不要用力按压水墨屏，对齐后左右按压排针两端就很容易进去了），然后将电源连接到电源接口（连接电源后注意不要用手接触电路板，防止静电击穿器件），等待一段时间（大约3分钟左右），它会自动启动进行孵化，此时不要关机!等待孵化结束后会进入自动模式自动开始捕获猎物（获取握手包）![7](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/a6d394231e6fe.jpg)

+ 3.等待获取的差不多以后，用micro-usb线连接数据接口至电脑（我用的是笔记本），它会进入手动模式

  > 我的电脑是win10，在插入电脑接口后会自动识别为串口设备，就需要去给它安装一个usb rndis驱动（这里我提供一个我找到的，[下载地址](https://wws.lanzous.com/iXjElmh7bhe)密码7d0z）![1](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/4aca0738e0513.png)
  >
  > 然后就会识别为Rndis网络接口（具体使用方法[点击](https://blog.csdn.net/vivian_ll/article/details/78261663?utm_medium=distribute.pc_relevant.none-task-blog-baidujs_baidulandingword-6&spm=1001.2101.3001.4242)）

  接下来右键这个网络-属性-双击Internet协议版本4，然后如图设置

  ![8](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/290f9813dc1e6.png)

  打开浏览器输入：你的宠物名.local:8080，然后会弹出一个窗口，输入你在配置文件中设定的账号密码（默认为changeme）

  ![2](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/77ce937175f05.png)

  你会发现这里也会实时显示你的pwnagotchi信息，并且还有很多其他的功能

  ![3](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/a23f2f9b475e9.png)

+ 4.当然连接电脑最大的用处还是导出握手包

  先打开cmd，用ssh去连接树莓派（shire是我的宠物名）密码为raspberry![4](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/3a984a3a72d60.png)

  我们的握手包存在/root/handshakes文件夹里，所以导出的话要先给权限，先输入sudo su 切换到root账户，然后再输入chmod 777 /root

  然后我这里我用filezilla来下载文件，用户名和密码分别是pi和raspberry![5](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/a13674caa67f3.png)

  然后进入/root/handshakes文件夹下载握手包就行

  ![6](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/770a3cda43d18.png)

## 手机访问pwnagotchi

+ 手机蓝牙连接树莓派后才能正常显示时间，手机开启蓝牙，同时开启蓝牙网络共享（不同的手机开启方式不同自行百度）然后树莓派就会向手机发出连接申请
  连接蓝牙后，就可以在手机浏览器访问pwnagotchi网页终端

## 握手包处理

+ 握手包的处理可以参照[hashcat破解wap/wap2](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)，我们获得的握手包是pcap文件，我们可以用[hashcat转换网站](https://hashcat.net/cap2hccapx/)转换为hccapx文件
+ 然后[hashcat](https://hashcat.net/hashcat/)官网下载windows的exe版本
+ 打开powershell(进入vscode在终端输入powershell)输入如图
  
  ![6](https://e4l4pic.oss-cn-beijing.aliyuncs.com/img/f5aee89f27db2.png)

  能不能跑出来完全看字典和算力了，hashcat具体使用方法可以自行搜索教程。

## 美化！

+ 淘宝店铺派星人厨房有卖3D打印外壳，和便携式电源，还不错，就是有点贵=-=
+ 带拉扣的外壳3d打印图纸分享：https://www.geekeyes.cn/forum.php?mod=viewthread&tid=1646

> 参考链接
> pwnagotchi官网：https://pwnagotchi.ai/
> 极客之眼官网汉化：https://www.geekeyes.cn/forum.php?mod=viewthread&tid=1105
> 【极客之眼】出击^o^,逆时空WiFi狩猎兽------极客专属的AI智能陪伴电子宠物设备!：https://www.bilibili.com/video/BV1wJ411B7YX
> 要电子宠物么？投喂WiFi的那种：https://www.bilibili.com/video/BV1Up4y1a7bE













