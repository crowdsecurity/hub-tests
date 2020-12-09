package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	leaky "github.com/crowdsecurity/crowdsec/pkg/leakybucket"
	"github.com/crowdsecurity/crowdsec/pkg/parser"
	"github.com/crowdsecurity/crowdsec/pkg/types"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

func parsePoMatchLine(event types.Event, parserCTX *parser.UnixParserCtx, parserNodes []parser.Node) (*types.Event, error) {
	var (
		err       error
		parsed    types.Event
		reprocess bool = false
	)
	oneResult := LineParsePoResult{}

	if event.Type == types.LOG {
		return &types.Event{}, errors.New(fmt.Sprintf("event %+v is not an overflow", event))
	}

	parsed, err = parser.Parse(*parserCTX, event, parserNodes) //truly, parser.Parse never returns any error...
	if err != nil {
		return &types.Event{}, errors.Wrap(err, "failed parsing : %v\n")
	}

	if parsed.Overflow.Reprocess {
		log.Infof("Pouring buckets reprocess")
		reprocess = true
		_, err = leaky.PourItemToHolders(parsed, holders, buckets)
	}

	if !parsed.Process {
		log.Errorf("Unaparsed line: %+v", parsed.Overflow)
	}

	parsed = sortAlerts(parsed)
	//marshal current result
	oneResult.Overflow = parsed.Overflow
	//we need to clean Line's timestamp
	oneResult.ParserResults = cleanForMatch(parser.StageParseCache)
	AllPoResults = append(AllPoResults, oneResult)
	if reprocess {
		return &parsed, nil
	}
	return nil, nil
}

func testPwfl(target_dir string, parsers *parser.Parsers, localConfig ConfigTest) error {
	var (
		matched      bool
		err          error
		parsed       *types.Event
		poInput      []types.Event = []types.Event{}
		bucketsInput []types.Event = []types.Event{}
	)
	log.Printf("Testing postoverflows")

	// Retrieve value from yaml
	// And once again we would have done better with generics...

	AllPoExpected = make([]LineParsePoResult, 0)
	AllPoResults = make([]LineParsePoResult, 0)

	if err = retrieveAndUnmarshal(target_dir+"/"+localConfig.PoInputFile, &poInput); err != nil {
		return errors.Wrapf(err, "Error unmarshaling %s", localConfig.PoInputFile)
	}

	unparsedOverflow := 0
	for _, evt := range poInput {
		parsed, err = parsePoMatchLine(evt, parsers.Povfwctx, parsers.Povfwnodes)
		if err != nil {
			log.Warningf("parser error : %s", err)
			unparsedOverflow++
		}
		if parsed != nil {
			bucketsInput = append(bucketsInput, *parsed)
		}
	}

	ExpectedPresent := false
	expectedPoResultsFile := target_dir + "/" + localConfig.PoResultFile

	expected_bytes, err := ioutil.ReadFile(expectedPoResultsFile)
	if err != nil {
		log.Warningf("no results in %s, will dump data instead!", target_dir)
		//there was no data present, just dump

	} else {
		if err := json.Unmarshal(expected_bytes, &AllPoExpected); err != nil {
			return errors.Wrapf(err, "file %s can't be unmarshaled", expectedPoResultsFile)
		} else {
			ExpectedPresent = true
			//			OrigExpectedLen = len(AllPoExpected)
		}
	}

	if !ExpectedPresent {
		log.Warningf("No expected results loaded, dump.")
		dump_bytes, err := json.MarshalIndent(AllPoResults, "", " ")
		if err != nil {
			errors.Wrap(err, "failed to marshal results")
		}
		if err := ioutil.WriteFile(expectedPoResultsFile, dump_bytes, 0644); err != nil {
			errors.Wrapf(err, "failed to dump data to %s", expectedPoResultsFile)
		}
	} else {
		if len(AllExpected) > 0 {
			log.Errorf("Left-over results in expected : %d", len(AllExpected))
		}
	}

	opt := getCmpOptions()
	deleted := 0
	for idx, candidate := range AllPoExpected {
		matched = false
		for _, result := range AllPoResults {
			//not our line
			log.Printf("Comparing")
			//			if !cmp.Equal(candidate.Overflow.APIAlerts[0].Source, result.Overflow.APIAlerts[0].Source) {
			if !cmp.Equal(candidate.Overflow, result.Overflow, opt) {
				//				log.Printf("mismatch diff (-want +got) : %s", cmp.Diff(candidate.Overflow.APIAlerts[0].Meta, result.Overflow.APIAlerts[0].Meta, opt))
				continue
			}
			log.Printf("We are comparing the results now")
			if cmp.Equal(candidate, result, opt) {
				matched = true
				//we go an exact match
				AllPoExpected = append(AllPoExpected[:idx-deleted], AllPoExpected[idx-deleted+1:]...)
				deleted++
			} else {
				return errors.New(fmt.Sprintf("mismatch diff (-want +got) : %s", cmp.Diff(candidate, result, opt)))
			}
			break
		}
	}

	if !matched && len(AllPoExpected) != 0 {
		expectedPoResultsFile = expectedPoResultsFile + ".fail"
		log.Errorf("tests failed, writing results to %s", expectedPoResultsFile)
		dump_bytes, err := json.MarshalIndent(AllResults, "", " ")
		if err != nil {
			errors.Wrap(err, "failed to marshal results")
		}
		if err := ioutil.WriteFile(expectedPoResultsFile, dump_bytes, 0644); err != nil {
			errors.Wrapf(err, "failed to dump data to %s", expectedPoResultsFile)
		}
		return errors.New(fmt.Sprintf("Result is not in the %d expected results", len(AllPoExpected)))
	}

	log.Infof("postoverflow tests are finished.")

	if len(bucketsInput) > 0 {
		if err = marshalAndStore(bucketsInput, target_dir+"/"+localConfig.ReprocessInputFile); err != nil {
			log.Errorf("Unable to marshal bucketsInput for reprocess stuff")
		}
	}
	return nil
}
