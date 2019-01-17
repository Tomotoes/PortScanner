#!/usr/bin/env bash
git add -A
echo "输入提交信息:"
read message
git commit -m "${message}"
git push -f origin master
