git add -A
if [ "$1" ]
then
    git commit -m "$1"
else
	git commit -m "commit"
fi
#git push origin wait_commit

git push origin no_remap_err
#git push origin master
#git push github master
