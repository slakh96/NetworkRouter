#!/bin/bash

scp -r -P 2222 mininet@127.0.0.1:/home/mininet/cs144_lab3/router ./ || { echo 'scp failed'; exit 1; }
git status
git add . 
echo 'Enter commit message here, or enter to skip:'
read msg
if [ ! -z "$msg" ]; then
	git commit -m "$msg" || exit 1
	git push || exit 1
else
	git commit -m "Updated router code" || exit 1
	git push || exit 1
fi
echo 'Code backed up to Github'
exit 0
