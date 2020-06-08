#!/bin/sh

go build main.go || exit
cp ./main ../ || exit
cp -R ./tests/ ../ || exit
