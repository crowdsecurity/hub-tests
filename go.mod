module github.com/crowdsecurity/hub-tests

go 1.13

require (
	github.com/crowdsecurity/crowdsec v0.0.0-00010101000000-000000000000
	github.com/google/go-cmp v0.4.1
	github.com/oschwald/maxminddb-golang v1.6.0
	github.com/sirupsen/logrus v1.6.0
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637
)

replace github.com/crowdsecurity/crowdsec => ../
