package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// type are stolen from https://github.com/jstemmer/go-junit-report/blob/master/formatter/formatter.go
// thanks to Joel Stemmer

// For we'll use a TestSuite for each type parser, scenario, postoverflow

// JUnitTestSuites is a collection of JUnit test suites.
type JUnitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []JUnitTestSuite `xml:"testsuite"`
}

// JUnitTestSuite is a single JUnit test suite which may contain many
// testcases.
type JUnitTestSuite struct {
	XMLName    xml.Name        `xml:"testsuite"`
	Tests      int             `xml:"tests,attr"`
	Failures   int             `xml:"failures,attr"`
	Time       string          `xml:"time,attr"`
	Name       string          `xml:"name,attr"`
	Properties []JUnitProperty `xml:"properties>property,omitempty"`
	TestCases  []JUnitTestCase `xml:"testcase"`
}

// JUnitTestCase is a single test case with its result.
type JUnitTestCase struct {
	XMLName     xml.Name          `xml:"testcase"`
	Classname   string            `xml:"classname,attr"`
	Name        string            `xml:"name,attr"`
	Time        string            `xml:"time,attr"`
	SkipMessage *JUnitSkipMessage `xml:"skipped,omitempty"`
	Failure     *JUnitFailure     `xml:"failure,omitempty"`
}

// JUnitSkipMessage contains the reason why a testcase was skipped.
type JUnitSkipMessage struct {
	Message string `xml:"message,attr"`
}

// JUnitProperty represents a key/value pair used to define properties.
type JUnitProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// JUnitFailure contains data related to a failed test.
type JUnitFailure struct {
	Message  string `xml:"message,attr"`
	Type     string `xml:"type,attr"`
	Contents string `xml:",chardata"`
}

func LoadJunitReport(filename string) (*JUnitTestSuites, error) {
	var (
		err error
		buf []byte
	)
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Debugf("File %s doesn't exist we'll create it late")
		return &JUnitTestSuites{}, nil
	}

	if buf, err = ioutil.ReadFile(filename); err != nil {
		return nil, errors.Wrapf(err, "Read file %s error: %s", filename)
	}

	report := &JUnitTestSuites{
		Suites: make([]JUnitTestSuite, 0),
	}
	err = xml.Unmarshal(buf, report)
	return report, err
}

func (report *JUnitTestSuites) AddSingleResult(itemType string, err error, name string) {
	var (
		index     int = 0
		failcount int = 0
		testCase  JUnitTestCase
		suite     JUnitTestSuite
		failure   *JUnitFailure
	)

	testCase = JUnitTestCase{}

	//first create the failure if any
	if err != nil {
		failure = &JUnitFailure{
			Message:  fmt.Sprint(err),
			Contents: fmt.Sprint(err),
		}
		failcount++
	} else {
		failure = nil
	}

	//create the TestCase
	testCase = JUnitTestCase{
		Classname: fmt.Sprintf("%s/%s", itemType, name),
		Name:      name,
		Failure:   failure,
	}

	//Look for a matching TestSuite and update it
	exists := false
	for _, s := range report.Suites {
		if suite.Name == itemType {
			suite = s
			exists = true
		}
	}

	if !exists {
		suite = JUnitTestSuite{
			Tests:     1,
			Failures:  failcount,
			Name:      name,
			TestCases: []JUnitTestCase{testCase},
		}
		report.Suites = []JUnitTestSuite{suite}
	} else {
		suite.Tests++
		if failure != nil {
			suite.Failures++
		}
		suite.TestCases = append(suite.TestCases, testCase)
		report.Suites[index] = suite
	}
}

func (report *JUnitTestSuites) StoreJunitReport(filename string) error {
	buf, err := xml.Marshal(report)
	if err != nil {
		return errors.Wrap(err, "Unable to store JUnit File")
	}
	if err = ioutil.WriteFile(filename, buf, 0644); err != nil {
		return errors.Wrapf(err, "Write file %s error", filename)
	}
	return nil
}
