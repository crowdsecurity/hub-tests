# hub-tests
Testing hub parsers

:warning: all tests are ran from crowdsec repo :warning:


```bash
#build release of crowdsec and test env
make release
#hub-tests must be cloned from crowdsec directory, as its go.mod makes crowdsec point to ../
git clone git@github.com:crowdsecurity/hub-tests.git
cd hub-tests
make
#go to crowdsec release dir
cd ../crowdsec-vXXX
./test_env.sh
cd tests
#copy CI binary and tests files to release's test directory
cp -R ../../hub-tests/tests .
cp ../../hub-tests/main .
#run the tests
./main -c dev.yaml ./tests/nginx-1
```

The "prep_tests.sh" script :
 - copies the `tests` dir
 - copies the binary file
 - install all the parsers with `cscli`
 

