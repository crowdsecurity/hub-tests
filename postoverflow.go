package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"
	"github.com/google/go-cmp/cmp"
	log "github.com/sirupsen/logrus"
)

func parsePoMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (bool, bool, types.Event, error) {
	var (
		err    error
		parsed types.Event
	)
	//	oneResult := LineParseResult{}

	oneResult := LineParsePoResult{}

	if event.Type == types.LOG {
		return true, false, types.Event{}, fmt.Errorf("event %+v is not an overflow", event)
	}

	parsed, err = parser.Parse(*parserCTX, event, parserNodes)
	if err != nil {
		return false, false, types.Event{}, fmt.Errorf("failed parsing : %v\n", err)
	}
	if parsed.Overflow.Reprocess {
		log.Infof("Pouring buckets")
		_, err = leaky.PourItemToHolders(parsed, holders, buckets)
	}
	if !parsed.Process {
		return true, false, types.Event{}, fmt.Errorf("unparsed line %s", parsed.Line.Raw)
	}

	//marshal current result
	oneResult.Overflow = parsed.Overflow
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)
	opt := getCmpOptions()

	/*
		Iterate over the list of expected results and try to find back
	*/
	AllPoResults = append(AllPoResults, oneResult)
	matched := false
	log.Printf("candidate: %+v", event)

	for idx, candidate := range AllPoExpected {
		//not our line
		if cmp.Equal(candidate.Overflow, event.Overflow) {
			continue
		}
		if cmp.Equal(candidate, oneResult, opt) {
			matched = true
			//we go an exact match
			AllPoExpected = append(AllPoExpected[:idx], AllPoExpected[idx+1:]...)
		} else {
			return false, true, types.Event{}, fmt.Errorf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, oneResult, opt))
		}
		break
	}

	if !matched && len(AllPoExpected) != 0 {
		return false, true, types.Event{}, fmt.Errorf("Result is not in the %d expected results", len(AllPoExpected))
	}
	return matched, true, parsed, nil
}

func checkResultPo(target_dir string, failure bool) {
	//there was no data present, just dump
	ExpectedPresent := false
	expectedResultsFile := target_dir + "/po_results.json"

	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}
	if failure {
		expectedResultsFile = expectedResultsFile + ".fail"
		log.Errorf("tests failed, writting results to %s", expectedResultsFile)
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			log.Fatalf("failed to marshal results : %s", err)
		}
		if err := ioutil.WriteFile(expectedResultsFile, dump_bytes, 0644); err != nil {
			log.Fatalf("failed to dump data to %s : %s", expectedResultsFile, err)
		}
		log.Printf("done")
		os.Exit(1)
	}
	log.Infof("parser tests are finished.")
}
