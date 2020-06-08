# hub-tests
Testing hub parsers

:warning: all tests are ran from crowdsec repo :warning:


```bash
#build release of crowdsec and test env
make release
cd crowdsec-vXXX
./test_env.sh
cd tests
#build CI
git clone git@github.com:crowdsecurity/hub-tests.git
cd hub-tests
go build main.go
cp ./main ../
cp -R ./tests ../
#run the tests
cd ..
./main ./tests/nginx-1
```

