---
title: ubuntu pwn 环境配置
date: 2021-09-18 12:44:59 +0800
categories:
  - ctf刷题
tags:
  - pwn
  - ctf
permalink: /posts/id=4/
pin: false
---



脚本测试版本: ubuntu22.04

更新测试版本：ubuntu20.04

第一步：安装pigcha挂代理/tips命令

```bash
#取消提示
touch ~/.sudo_as_admin_successful
# apt 换源
cp /etc/apt/sources.list /etc/apt/sources.list.bak#备份
sudo gedit /etc/apt/sources.list
# 网上找对应版本的阿里源即可
# 复制粘贴覆盖到打开的sources.list里
sudo apt-get update
# ubuntu22.04只能用命令行端！！！
http://pigcha.com/
sudo dpkg --add-architecture i386 && sudo dpkg -i PigchaClient.deb
# 安装Vscode
# 网上下载即可



#-------------------------------tips--------------------------------------
# 查看挂载
df -Th
# 解压bz2
tar jxvf FileName.tar.bz2
tar czf rootfs.tar.gz ./rootfs
tar -zxvf ./rootfs.tar.gz
# 配置环境变量
sudo gedit /etc/profile
#这个文件不是保存环境变量信息的文件，在登录时，系统只是根据它的内容对环境变量进行设置。
#其中，各个PATH之间用冒号分隔，$PATH指代添加your path前的环境变量。
# /home/e4l4/.local/bin
export PATH=$PATH:/home/e4l4/.local/bin

```

tips:[PPA失败解决](https://blog.csdn.net/qq_33475105/article/details/82084589?utm_medium=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.baidujs&depth_1-utm_source=distribute.pc_relevant_t0.none-task-blog-2%7Edefault%7EBlogCommendFromMachineLearnPai2%7Edefault-1.baidujs)

第二步：安装环境

inint.sh（脚本不一定能直接运行，建议分段测试）

```bash
#!/bin/bash
set -e
cd ~
sudo apt-get -y update
sudo apt-get -y install tzdata
sudo apt-get -y install vim
sudo apt-get -y install libxml2-dev
sudo apt-get -y install libxslt-dev
sudo apt-get -y install libmysqlclient-dev
sudo apt-get -y install libsqlite3-dev
sudo apt-get -y install zlib1g-dev
sudo apt-get -y install python2-dev
sudo apt-get -y install libffi-dev
sudo apt-get -y install libssl-dev
sudo apt-get -y install wget
sudo apt-get -y install curl
sudo apt-get -y install gcc
sudo apt-get -y install clang
sudo apt-get -y install make
sudo apt-get -y install zip
sudo apt-get -y install build-essential
sudo apt-get -y install libncursesw5-dev libgdbm-dev libc6-dev
sudo apt-get -y install tk-dev
sudo apt-get -y install openssl
sudo apt-get -y install virtualenv
sudo apt-get -y install git
sudo apt-get -y install net-tools
sudo apt-get -y install proxychains4


#setuptools 36.6.1 -> python2
wget https://mirrors.aliyun.com/pypi/packages/56/a0/4dfcc515b1b993286a64b9ab62562f09e6ed2d09288909aee1efdb9dde16/setuptools-36.6.1.zip
unzip setuptools-36.6.1.zip
cd setuptools-36.6.1
sudo python2 setup.py install
cd ../
sudo rm -rf setuptools-36.6.1 setuptools-36.6.1.zip

#setuptools 65.4.1 -> python3
wget https://mirrors.aliyun.com/pypi/packages/03/c9/7b050ea4cc4144d0328f15e0b43c839e759c6c639370a3b932ecf4c6358f/setuptools-65.4.1.tar.gz
tar -zxvf setuptools-65.4.1.tar.gz
cd setuptools-65.4.1
sudo python3 setup.py install
cd ../
sudo rm -rf setuptools-65.4.1 setuptools-65.4.1.tar.gz

#pip
wget https://mirrors.aliyun.com/pypi/packages/53/7f/55721ad0501a9076dbc354cc8c63ffc2d6f1ef360f49ad0fbcce19d68538/pip-20.3.4.tar.gz
tar -zxvf pip-20.3.4.tar.gz
cd pip-20.3.4
sudo python2 setup.py install
sudo python3 setup.py install # ubuntu20.04: sudo apt install python3-pip
cd ../
sudo rm -rf pip-20.3.4 pip-20.3.4.tar.gz

sudo pip2 config set global.index-url https://mirrors.aliyun.com/pypi/simple
sudo pip3 config set global.index-url https://mirrors.aliyun.com/pypi/simple

sudo python2 -m pip install --upgrade pip
sudo python3 -m pip install --upgrade pip

sudo pip2 install pathlib2

#pwntools
sudo pip2 install pwntools
sudo pip3 install pwntools

#pwndbg
# source ~/.gef-a85368fc771dcbb4db2b41818781e182845015b9.py
git clone https://github.com/pwndbg/pwndbg.git
cd pwndbg
./setup.sh
cd ../

#Pwngdb
git clone https://github.com/scwuaptx/Pwngdb.git
cp ~/Pwngdb/.gdbinit ~/
sed -i 'N;2 i source ~/pwndbg/gdbinit.py' ~/.gdbinit
sed -i '/peda/d' ~/.gdbinit

#ln python2 -> python
sudo update-alternatives --install /usr/bin/python python /usr/bin/python2 1
sudo update-alternatives --install /usr/bin/python python /usr/bin/python3 2
sudo update-alternatives --config python

#one_gadget
sudo apt-get -y install ruby-dev
sudo gem install one_gadget --verbose
# 20.04 需要先进行root账户下的gem换源
sudo -i
gem sources --remove https://rubygems.org/
gem sources --add https://mirrors.aliyun.com/rubygems/

#seccomp-tools
sudo gem install seccomp-tools

#patchelf
sudo apt-get -y install patchelf

#glibc-all-in-one
git clone https://github.com/matrix1001/glibc-all-in-one.git
cd glibc-all-in-one
./update_list
cd ../


#ropper
sudo pip3 install capstone filebytes unicorn keystone-engine ropper

#qemu-system
sudo apt-get install qemu-system

# xclibc
git clone https://github.com/ef4tless/xclibc.git
cd xclibc
sudo rm /usr/local/bin/xclibc
sudo mv ./xclibc /usr/local/bin
sudo chmod +x /usr/local/bin/xclibc
cd ../

# musl_debug
wget http://e4l4.com/musl_1.2.2-1_amd64.deb
wget http://e4l4.com/musl-dbgsym_1.2.2-1_amd64.ddeb
sudo dpkg -i musl_1.2.2-1_amd64.deb
sudo dpkg -i musl-dbgsym_1.2.2-1_amd64.ddeb
sudo rm -rf musl_1.2.2-1_amd64.deb musl-dbgsym_1.2.2-1_amd64.ddeb
cd ../

# muslheap
git clone https://github.com/xf1les/muslheap.git
cd muslheap
echo "source ~/muslheap/muslheap.py" >> ~/.gdbinit

# 修复pwntools-python2
cd ~/.local/lib/python2.7/site-packages
wget -r http://e4l4.com/unicorn-2.0.0rc7.dist-info
wget -r http://e4l4.com/unicorn
rm -rf unicorn/ unicorn-2.0.1.post1.dist-info/
mv e4l4.com/unicorn-2.0.0rc7.dist-info/ .
mv e4l4.com/unicorn .
rm -rf e4l4.com
# ubuntu20.04
cd /usr/local/lib/python2.7/dist-packages
sudo wget -r http://e4l4.com/unicorn-2.0.0rc7.dist-info
sudo wget -r http://e4l4.com/unicorn
sudo rm -rf unicorn/ unicorn-2.0.1.post1.dist-info/
sudo mv e4l4.com/unicorn-2.0.0rc7.dist-info/ .
sudo mv e4l4.com/unicorn .
sudo rm -rf e4l4.com

# tmux
sudo apt install tmux
git clone https://github.com/gpakosz/.tmux.git
ln -s -f .tmux/.tmux.conf
cp .tmux/.tmux.conf.local .

# 挂载ctf文件夹
vmware-hgfsclient # 列出上述共享文件夹名称
sudo mkdir -p /mnt/hgfs
sudo /usr/bin/vmhgfs-fuse .host:/ /mnt/hgfs -o subtype=vmhgfs-fuse,allow_other
ls -l /mnt/hgfs
sudo gedit /etc/fstab
# 写在结尾
.host:/    /mnt/hgfs    fuse.vmhgfs-fuse allow_other,defaults    0    0
# 重启虚拟机


# zsh
sudo apt install zsh
sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

git clone https://github.com/zsh-users/zsh-autosuggestions.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions

git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

git clone https://github.com/zsh-users/zsh-completions ${ZSH_CUSTOM:-${ZSH:-~/.oh-my-zsh}/custom}/plugins/zsh-completions
fpath+=${ZSH_CUSTOM:-${ZSH:-~/.oh-my-zsh}/custom}/plugins/zsh-completions/src

code ~/.zshrc

plugins=(
  git
  zsh-autosuggestions
  zsh-syntax-highlighting
  zsh-completions
)

source ~/.zshrc
```

