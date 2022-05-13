#/bin/bash
function deploy()
{
git add *
	echo "Successful execution of git add *"
git commit -m "e4l4"
	echo "Successful execution of hexo git commit"
git push -u origin main
	echo -e "\033[32mUpload successfully performed!\033[0m"
	echo -e "\033[36mBut you had better check your github\033[0m"
}

deploy
