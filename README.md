# hub-tests
Testing hub parsers

:warning: all tests are ran from crowdsec repo :warning:


```bash
#build CI
git clone git@github.com:crowdsecurity/hub-tests.git
cd hub-tests && bash prep_tests.sh
#build release of crowdsec and test env
make release
cd crowdsec-vXXX
./test_env.sh
cd tests
#run the tests
cd ..
./main ./tests/nginx-1
```

The "prep_tests.sh" script :
 - copies the `tests` dir
 - copies the binary file
 - install all the parsers with `cscli`
 

