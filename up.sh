# 确保脚本抛出遇到的错误
set -e
 
# 获取当前时间
now=$(date "+%Y-%m-%d%H:%M")
 
echo "正在上传源代码..."

git config --global user.email "963697159@qq.com"
git config --global user.name "ef4tless"
git init
git add -A
git commit -m "代码提交$now"
git push -u origin main
echo "上传完成"
# 具体git命令根据自身需求更改
 
cd -