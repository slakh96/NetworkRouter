#!/bin/bash
#Script which syncs my work from my VM o github; as VM does not have internet connectivity
scp -r -P 2222 mininet@127.0.0.1:/home/mininet/cs144_lab3/router ./ || { echo 'scp failed'; exit 1; }
cd router
make clean
cd ..
git add .
git status
echo 'Enter commit message here, or press enter to use default message:'
read msg
if [ ! -z "$msg" ]; then
	git commit -a -m "$msg" || exit 1
	git push || exit 1
else
	git commit -a -m "Updated router code" || exit 1
	git push || exit 1
fi
echo 'Code backed up to Github'
exit 0
