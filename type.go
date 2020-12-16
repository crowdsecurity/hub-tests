package main

import "github.com/crowdsecurity/crowdsec/pkg/types"

type TestParsers struct {
	current         string //meant to be parsers or postoverflows
	LocalConfig     *ConfigTest
	ParserResult    *ParserResults
	ResultFile      string
	ExpectedPresent bool
}

type ParserResults struct {
	ProvisionalResults []map[string]map[string]types.Event
	FinalResults       []types.Event
}
