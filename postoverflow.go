package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

func parsePoMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, error) {
	var (
		err    error
		parsed types.Event
	)
	//	oneResult := LineParseResult{}

	oneResult := LineParsePoResult{}

	if event.Type == types.LOG {
		return false, fmt.Errorf("event %+v is not an overflow", event)
	}

	parsed, err = parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, fmt.Errorf("failed parsing : %v\n", err)
	}
	if parsed.Overflow.Reprocess {
		log.Infof("Pouring buckets")
		_, err = leaky.PourItemToHolders(parsed, holders, buckets)
	}
	if !parsed.Process {
		return false, fmt.Errorf("unparsed line %+v", parsed.Overflow)
	}

	//marshal current result
	oneResult.Overflow = parsed.Overflow
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)

	/*
		Iterate over the list of expected results and try to find back
	*/
	AllPoResults = append(AllPoResults, oneResult)
	return true, nil
}

func checkResultPo(target_dir string, failure bool) error {
	var matched bool
	//there was no data present, just dump
	ExpectedPresent := false
	expectedPoResultsFile := target_dir + "/po_results.json"

	expected_bytes, err := ioutil.ReadFile(expectedPoResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", target_dir)
	} else {
		if err := json.Unmarshal(expected_bytes, &AllPoExpected); err != nil {
			log.Fatalf("file %s can't be unmarshaled : %s", expectedPoResultsFile, err)
		} else {
			ExpectedPresent = true
			//			OrigExpectedLen = len(AllPoExpected)
		}
	}

	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllPoResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedPoResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedPoResultsFile, err)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}

	opt := getCmpOptions()
	log.Printf("AllPoExpected: %+v", AllPoExpected)
	for idx, candidate := range AllPoExpected {
		matched = false
		for _, result := range AllPoResults {
			//not our line
			if !cmp.Equal(candidate.Overflow, result.Overflow) {
				continue
			}
			if cmp.Equal(candidate, result, opt) {
				matched = true
				//we go an exact match
				AllPoExpected = append(AllPoExpected[:idx], AllPoExpected[idx+1:]...)
			} else {
				return fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, result, opt))
			}
			break
		}
	}

	if !matched && len(AllPoExpected) != 0 {
		expectedPoResultsFile = expectedPoResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedPoResultsFile)
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedPoResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedPoResultsFile, err)
		}
		return fmt.Errorf("Result is not in the %d expected results", len(AllPoExpected))
	}
	log.Infof("postoverflow tests are finished.")
	return nil
}
