#!/bin/sh

for i in `find ./tests -mindepth 1 -maxdepth 1 -type d` ; do
    ./main $i || (echo "Failed test for ${i}" ; diff ${i}"/results.yaml" ${i}"/results.yaml.fail" ; exit 1) ;
done
