#!/bin/sh

go build main.go || exit
cp ./main ../ || exit
cp -R ./tests/ ../ || exit
cd ../ && for i in `./cscli -c dev.yaml list parsers -a -o json | jq -r ".[].name" ` ; do ./cscli -c dev.yaml install parser $i ; done
